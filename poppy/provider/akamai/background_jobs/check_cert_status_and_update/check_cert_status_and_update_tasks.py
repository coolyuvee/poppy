# Copyright (c) 2015 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Checks and updates the status of certificates.

The module has below tasks defined in it and will be
called when the parent flow is loaded into Taskflow
engine:
    - Get the certificate for a given details
    - Determine the needed status for the certificate
    - Update the certificate with that status
"""

import json

from oslo_config import cfg
from oslo_log import log
from taskflow import task

from poppy.distributed_task.utils import memoized_controllers
from poppy.transport.pecan.models.request import ssl_certificate


LOG = log.getLogger(__name__)
conf = cfg.CONF
conf(project='poppy', prog='poppy', args=[])


class GetCertInfoTask(task.Task):
    """Get the certificate object.

    Fetch the certificate details from cassandra storage
    for the below given values:
         - domain name
         - certificate type
         - flavor id
         - project id

    Serialize the certificate details and return.

    The returned value will be assigned to the variable
    ``cert_obj_json`` and consumed by the next Task
    in the flow :class:`CheckCertStatusTask` to check the status.
    """
    default_provides = "cert_obj_json"

    def execute(self, domain_name, cert_type, flavor_id, project_id):
        """Return certificate details.

        :param unicode domain_name: The domain name
        :param unicode cert_type: Type of the certificate
        :param unicode flavor_id: Flavor id
        :param unicode project_id: Project id

        :return: Serialized dict of certificate details
        :rtype: str
        """
        service_controller, self.ssl_certificate_manager = \
            memoized_controllers.task_controllers('poppy', 'ssl_certificate')
        self.storage = self.ssl_certificate_manager.storage

        res = self.storage.get_certs_by_domain(
            domain_name, project_id=project_id,
            flavor_id=flavor_id, cert_type=cert_type)
        if res is None:
            return ""
        return json.dumps(res.to_dict())


class CheckCertStatusTask(task.Task):
    """Determine the correct status for the certificate."""
    default_provides = "status_change_to"

    def __init__(self):
        super(CheckCertStatusTask, self).__init__()
        service_controller, self.providers = \
            memoized_controllers.task_controllers('poppy', 'providers')
        self.akamai_driver = self.providers['akamai'].obj

    def execute(self, cert_obj_json):
        """Get the status for the certificate based on its type.

        The ``cert_obj_json`` will be an output from the
        previous task in the flow :class:`GetCertInfoTask`.

        For SAN types, Makes call to Akamai SPS API and inspects the status
        returned from Akamai.

        Below are expected status from Akamai for SAN:
            - 'SPS Request Complete'
            - 'edge host already created or pending'
            - 'CPS cancelled'

        Return a new status for the certificate based on the
        SPS response status. If the status is other than the
        above mentioned list, then send the certificate to
        ``san mapping queue``.

        For SNI types, Makes call to CPS API and gets list of
        pending changes. If the ``change url`` is still present
        under pending changes, put the certificate details into
        ``san mapping queue`` for future check. Else, return a
        status the certificate should have.

        In either of the cert types, the returned value will be
        assigned to a variable ``status_change_to`` which will
        be consumed by the next task :class:`UpdateCertStatusTask`
        in the flow pipeline.

        :param str cert_obj_json: Serialized certificate details

        :return: Status needs to be set for the certificate
        :rtype: str

        :raises RuntimeError: If Akamai SPS request failed
        """
        if cert_obj_json != "":
            cert_obj = ssl_certificate.load_from_json(
                json.loads(cert_obj_json))
            if cert_obj.cert_type == 'san':
                latest_sps_id = cert_obj.\
                    cert_details['Akamai']['extra_info'].get(
                        'akamai_spsId')
                current_status = cert_obj.\
                    cert_details['Akamai']['extra_info'].get(
                        'status')

                if latest_sps_id is None:
                    return current_status

                resp = self.akamai_driver.akamai_sps_api_client.get(
                    self.akamai_driver.akamai_sps_api_base_url.format(
                        spsId=latest_sps_id
                    )
                )

                if resp.status_code != 200:
                    raise RuntimeError('SPS API Request Failed'
                                       'Exception: %s' % resp.text)

                sps_request_info = json.loads(resp.text)['requestList'][0]
                status = sps_request_info['status']
                workFlowProgress = sps_request_info.get(
                    'workflowProgress')

                # This SAN Cert is on pending status
                if status == 'SPS Request Complete':
                    LOG.info("SPS completed for %s..." %
                             cert_obj.get_edge_host_name())
                    return "deployed"
                elif status == 'edge host already created or pending':
                    if workFlowProgress is not None and \
                            'error' in workFlowProgress.lower():
                        LOG.info("SPS Pending with Error:" %
                                 workFlowProgress)
                        return "failed"
                    else:
                        return "deployed"
                elif status == 'CPS cancelled':
                    return "cancelled"
                else:
                    LOG.info(
                        "SPS Not completed for domain {0}, san_cert {1}. "
                        "Found status {2}. "
                        "Returning certificate object to Queue.".format(
                            cert_obj.domain_name,
                            cert_obj.get_edge_host_name(),
                            status
                        )
                    )
                    # convert cert_obj_json from unicode -> string
                    # before enqueue
                    self.akamai_driver.san_mapping_queue.enqueue_san_mapping(
                        json.dumps(cert_obj.to_dict()))
                    return ""
            elif cert_obj.cert_type == 'sni':
                change_url = cert_obj.cert_details['Akamai']['extra_info'].get(
                    'change_url')
                current_status = cert_obj.\
                    cert_details['Akamai']['extra_info'].get(
                        'status')

                if change_url is None:
                    return current_status

                enrollment_id = self.akamai_driver.cert_info_storage.\
                    get_cert_enrollment_id(cert_obj.get_edge_host_name())

                headers = {
                    'Accept': (
                        'application/vnd.akamai.cps.enrollment.v1+json')
                }
                resp = self.akamai_driver.akamai_cps_api_client.get(
                    self.akamai_driver.akamai_cps_api_base_url.format(
                        enrollmentId=enrollment_id
                    ),
                    headers=headers
                )
                if resp.status_code not in [200, 202]:
                    LOG.error(
                        "Unable to retrieve enrollment while attempting"
                        "to update cert status. Status {0} Body {1}".format(
                            resp.status_code,
                            resp.text
                        )
                    )
                    return current_status
                resp_json = json.loads(resp.text)

                pending_changes = resp_json["pendingChanges"]
                dns_names = (
                    resp_json["networkConfiguration"]["sni"]["dnsNames"]
                )

                if change_url not in pending_changes:
                    if cert_obj.domain_name in dns_names:
                        return "deployed"
                    else:
                        return "failed"
                else:
                    # the change url is still present under pending changes,
                    # return the item to the queue. another attempt to
                    # check and update the cert status should happen
                    self.akamai_driver.san_mapping_queue.enqueue_san_mapping(
                        json.dumps(cert_obj.to_dict()))
                    return current_status


class UpdateCertStatusTask(task.Task):
    """Update the certificate status"""

    def __init__(self):
        super(UpdateCertStatusTask, self).__init__()
        service_controller, self.ssl_certificate_manager = \
            memoized_controllers.task_controllers('poppy', 'ssl_certificate')
        self.storage_controller = (
            self.ssl_certificate_manager.storage
        )
        self.service_storage = service_controller.storage_controller

    def execute(self, project_id, cert_obj_json, status_change_to):
        """Update certificate and provider details.

        The ``status_change_to`` will be an output from the
        previous task in the flow :class:`CheckCertStatusTask`.

        :param unicode project_id: The project id
        :param str cert_obj_json: Certificate details
        :param str status_change_to: New status for the certificate
        """
        if not cert_obj_json:
            return
        cert_obj = ssl_certificate.load_from_json(
            json.loads(cert_obj_json)
        )
        cert_details = cert_obj.cert_details

        if status_change_to:
            cert_details['Akamai']['extra_info']['status'] = (
                status_change_to)
            cert_details['Akamai'] = json.dumps(cert_details['Akamai'])
            self.storage_controller.update_certificate(
                cert_obj.domain_name,
                cert_obj.cert_type,
                cert_obj.flavor_id,
                cert_details
            )

            service_obj = (
                self.service_storage.
                get_service_details_by_domain_name(cert_obj.domain_name)
            )
            # Update provider details
            if service_obj:
                service_obj.provider_details['Akamai'].\
                    domains_certificate_status.\
                    set_domain_certificate_status(cert_obj.domain_name,
                                                  status_change_to)
                self.service_storage.update_provider_details(
                    project_id,
                    service_obj.service_id,
                    service_obj.provider_details
                )
        else:
            pass

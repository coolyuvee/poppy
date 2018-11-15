# Copyright (c) 2014 Rackspace, Inc.
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

import json

from oslo_config import cfg
from oslo_log import log
from taskflow import task

from poppy.distributed_task.utils import memoized_controllers
from poppy.transport.pecan.models.request import ssl_certificate

LOG = log.getLogger(__name__)

conf = cfg.CONF
conf(project='poppy', prog='poppy', args=[])


class CreateProviderSSLCertificateTask(task.Task):
    default_provides = ("ssl_responders", "cert_domains")

    def execute(self, providers_list_json, cert_list_json, enqueue=False,
                https_upgrade=False):
        service_controller = memoized_controllers.task_controllers('poppy')
        providers_list = json.loads(providers_list_json)

        cert_obj_list = json.loads(cert_list_json)
        ssl_responders = []
        cert_domains = []

        # try to create all certificates from each provider
        for provider in providers_list:
            for cert_obj in cert_obj_list:
                if not cert_obj:
                    # This means the domain was HTTP
                    # No Need to create provider certificate
                    ssl_responders.append([])
                    cert_domains.append(None)
                else:
                    cert_obj = ssl_certificate.load_from_json(cert_obj)
                    LOG.info('Starting to create ssl certificate: {0}'
                             'from {1}'.format(cert_obj.to_dict(), provider))
                    responder = service_controller.provider_wrapper.create_certificate(
                        service_controller._driver.providers[provider],
                        cert_obj,
                        enqueue,
                        https_upgrade
                    )
                    ssl_responders.append({cert_obj.domain_name:responder})
                    cert_domains.append({cert_obj.domain_name:responder['Akamai']['cert_domain']})

        return ssl_responders, cert_domains


class SendNotificationTask(task.Task):

    def execute(self, project_id, ssl_responders, upgrade=False):
        service_controller = memoized_controllers.task_controllers('poppy')

        notification_content = ""
        for responder in ssl_responders:
            for provider in responder:
                notification_content += (
                    "Project ID: %s, Provider: %s, Detail: %s" %
                    (project_id, provider, str(responder[provider])))

        if upgrade is True:
            notification_content += (
                " The domain was upgraded from HTTP to HTTPS SAN. "
                "If applicable, take note of the domain name and "
                "delete the old HTTP policy in the provider."
            )

        for n_driver in service_controller._driver.notification:
            service_controller.notification_wrapper.send(
                n_driver,
                n_driver.obj.notification_subject,
                notification_content)

        return


class UpdateCertInfoTask(task.Task):

    def execute(self, project_id, cert_list_json, ssl_responders):

        service_controller, self.ssl_certificate_manager = \
            memoized_controllers.task_controllers('poppy', 'ssl_certificate')
        self.storage_controller = self.ssl_certificate_manager.storage

        cert_obj_list = json.loads(cert_list_json)
        for cert_obj in cert_obj_list:
            if cert_obj:
                cert_obj = ssl_certificate.load_from_json(cert_obj)
                for responder in ssl_responders:
                    for k,v in responder.items():
                        if cert_obj.domain_name == k:
                            provider_details = v
                            for provider in provider_details:
                                cert_details = {}
                                cert_details[provider] = json.dumps(provider_details[provider])
                                self.storage_controller.update_certificate(
                                    cert_obj.domain_name,
                                    cert_obj.cert_type,
                                    cert_obj.flavor_id,
                                    cert_details
                                )
                            break


        return


class CreateStorageSSLCertificateTask(task.Task):
    """This task is meant to be used in san rerun flow."""

    def execute(self, project_id, cert_list_json):
        cert_obj_list = json.loads(cert_list_json)
        cert_obj = ssl_certificate.load_from_json(cert_obj_list[0])

        service_controller, self.ssl_certificate_manager = \
            memoized_controllers.task_controllers('poppy', 'ssl_certificate')
        self.storage_controller = self.ssl_certificate_manager.storage

        try:
            self.storage_controller.create_certificate(project_id, cert_obj)
        except ValueError as e:
            LOG.exception(e)

    def revert(self, *args, **kwargs):
        try:
            if getattr(self, 'storage_controller') \
                    and self.storage_controller._driver.session:
                self.storage_controller._driver.close_connection()
                LOG.info('Cassandra session being shutdown')
        except AttributeError:
            LOG.info('Cassandra session already shutdown')

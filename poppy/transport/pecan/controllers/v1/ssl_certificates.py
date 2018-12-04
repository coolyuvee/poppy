# Copyright (c) 2014 Rackspace, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http:..www.apache.org.licenses.LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Pecan router to map SSL certificate related URLs.

The :class:`SSLCertificateController` does below
operations.

 - Create certificate dictionary in Cassandra
 - Create a new CPS certificate
 - Delete an existing certificate
 - Fetch details for a given domain


Pecan Mappings:-

 Each HTTP method is mapped to Pecan's method as shown below.

 Pecan Method     HttpMethod and URL
 -------------   -------------------------
 get_one         -> GET {{host}}/v1.0/ssl_certificate/<ssl_certificate-id>/
 post            -> POST /ssl_certificate/
 delete          -> DELETE /ssl_certificate/<ssl_certificate-id>/

 Example:-

   - The URL ``{{host}}/v1.0/ssl_certificate/ with HTTP POST`` will be received by
     :py:func:`SSLCertificateController.post()``
   - The URL ``{{host}}/v1.0/ssl_certificate/abc.domain.com with HTTP POST`` will be received by
     :py:func:`SSLCertificateController.get_one()``

The :class:`SSLCertificateController` have Enabled Context Hook and Errors Hook.
`Context Hook` checks that `X-Project-ID` and `X-Auth-Token`
are present in the request payload and constructs `base_url`.
`Errors Hook` handles any errors during the request.

``validate`` decorators are injected into each method of the class
to validate the payload and other dependencies. If any of the
validation fails, operation will be aborted and ``Errors Hook``
will be responsible for sending error response to the user.

After doing the base level validations on the request
payload, calls will be delegated to  Manager layer to
process the request. The Default Manager layer has
various controllers to handle these requests.

For more details on how the top level URL mapping is done, refer to
:py:mod:`poppy.poppy.transport.pecan.driver.py`
"""
import json

import pecan
from pecan import hooks

from poppy.transport.pecan.controllers import base
from poppy.transport.pecan import hooks as poppy_hooks
from poppy.transport.pecan.models.request import ssl_certificate
from poppy.transport.pecan.models.response import ssl_certificate \
    as ssl_cert_model
from poppy.transport.validators import helpers
from poppy.transport.validators.schemas import ssl_certificate\
    as ssl_certificate_validation
from poppy.transport.validators.stoplight import decorators
from poppy.transport.validators.stoplight import helpers as stoplight_helpers
from poppy.transport.validators.stoplight import rule


class SSLCertificateController(base.Controller, hooks.HookController):
    """Create,Delete,GET SSL certificates for domains"""

    __hooks__ = [poppy_hooks.Context(), poppy_hooks.Error()]

    @pecan.expose('json')
    @decorators.validate(
        request=rule.Rule(
            helpers.json_matches_service_schema(
                ssl_certificate_validation.SSLCertificateSchema.get_schema(
                    "ssl_certificate",
                    "POST")),
            helpers.abort_with_message,
            stoplight_helpers.pecan_getter))
    def post(self):
        """Create an SSL certificate for HTTPS domains.

        After the base level validations, this request will
        reach to Default manager.

        Default Manager will ..

         - Call Storage layer(Cassandra) to store the certificate details
         - Invokes ``create_ssl_certificate`` `Taskflow` to create provider
           certificates

        The ``create_ssl_certificate`` will ..
         - ``Enqueue`` flag(which is by default `True`) determines
           whether or not to create the certificate right now
         - If ``Enqueue`` is `True`, it simply adds this request
           to `mod_san_queue` and returns
         - Else,

            - It will look for an available provider certificate
            - If there is any available certificate, makes CPS call
              to the provider requesting to add this domain to
              that certificate
            - Else, again this request will be added to
              `mod_san_queue`.

        All the requests enqueued in `mod_san_queue` will be processed
        by admin job `rerun_retry_list`.

        :return: Pecan's 200 response If the request to add
         this domain to a certificate is successful or enqueued
         into `mod_san_queue`. 400 response will be returned
         if there was any error while doing so.
        :rtype: pecan.Response
        """
        ssl_certificate_controller = (
            self._driver.manager.ssl_certificate_controller)

        certificate_info_dict = json.loads(pecan.request.body.decode('utf-8'))

        try:
            project_id = certificate_info_dict.get('project_id')
            cert_obj = ssl_certificate.load_from_json(certificate_info_dict)
            cert_obj.project_id = project_id
            ssl_certificate_controller.create_ssl_certificate(project_id,
                                                              cert_obj)
        except LookupError as e:
            pecan.abort(400, detail='Provisioning ssl certificate failed. '
                        'Reason: %s' % str(e))
        except ValueError as e:
            pecan.abort(400, detail='Provisioning ssl certificate failed. '
                        'Reason: %s' % str(e))

        return pecan.Response(None, 202)

    @pecan.expose('json')
    @decorators.validate(
        domain_name=rule.Rule(
            helpers.is_valid_domain_by_name(),
            helpers.abort_with_message)
    )
    def delete(self, domain_name):
        """Delete domain from a service.

        Deleting domain involves ...
         - Deleting the certificate dictionary from cassandra
         - Deleting associated provider certificates
         - Deleting the respective DNS mappings

        All the three tasks are executed by the
        ``delete_ssl_certificate`` taskflow which is
        invoked from Default manager layer.

        :param unicode domain_name: The name of the domain
        :return: Pecan's 200 response if successfully invoked
         the delete_ssl_certificate taskflow. Else, 400 response
         will be returned.
        """
        # For now we only support 'san' cert type
        cert_type = pecan.request.GET.get('cert_type', 'san')

        certificate_controller = \
            self._driver.manager.ssl_certificate_controller
        try:
            certificate_controller.delete_ssl_certificate(
                self.project_id, domain_name, cert_type
            )
        except ValueError as e:
            pecan.abort(400, detail='Delete ssl certificate failed. '
                        'Reason: %s' % str(e))

        return pecan.Response(None, 202)

    @pecan.expose('json')
    @decorators.validate(
        domain_name=rule.Rule(
            helpers.is_valid_domain_by_name(),
            helpers.abort_with_message)
    )
    def get_one(self, domain_name):
        """Get domain details for a given domain name.

        :param unicode domain_name: The Name of the domain
        :return: Serialized SSLCertificate object in the
         form of collections.OrderedDict
        :rtype: collections.OrderedDict
        """

        certificate_controller = \
            self._driver.manager.ssl_certificate_controller
        total_cert_info = []

        try:
            # NOTE(TheSriram): we can also enforce project_id constraints
            certs_info = certificate_controller.get_certs_info_by_domain(
                domain_name=domain_name,
                project_id=None)
        except ValueError:
            pecan.abort(404, detail='certificate '
                                    'could not be found '
                                    'for domain : %s' %
                        domain_name)
        else:
            # convert a cert model into a response cert model
            try:
                if iter(certs_info):
                    for cert in certs_info:
                        total_cert_info.append(ssl_cert_model.Model(cert))
                    return total_cert_info
            except TypeError:
                return ssl_cert_model.Model(certs_info)

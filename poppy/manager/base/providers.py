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

from poppy.common import errors


class ProviderWrapper(object):
    """"ProviderWrapper class."""

    def create(self, ext, service_obj):
        """Create a provider.

        :param ext:
        :type ext: obj

        :param service_obj: The service details
        :type service_obj: dict

        :return: ext.obj.service_controller.create(service_obj)
        :rtype: ext.obj.service_controller.create
        """

        return ext.obj.service_controller.create(service_obj)

    def update(self, ext, provider_details, service_obj):
        """Update a provider.

        :param ext:
        :type ext: object

        :param provider_details: The provider details
        :type provider_details: dict

        :param service_obj: The service details
        :type service_obj: dict

        :return: Updated service details
        :rtype: dict
        """

        try:
            provider_detail = provider_details[ext.obj.provider_name]
        except KeyError:
            raise errors.BadProviderDetail(
                "No provider detail information."
                "Perhaps service has not been created")
        provider_service_id = provider_detail.provider_service_id
        return ext.obj.service_controller.update(
            provider_service_id, service_obj)

    def delete(self, ext, provider_details, project_id):
        """Delete a service.

        :param ext:
        :type ext: object

        :param provider_details: The provider details
        :type provider_details: dict

        :param project_id: The project id
        :type project_id: int
        """
        try:
            provider_detail = provider_details[ext.obj.provider_name]
        except KeyError:
            raise errors.BadProviderDetail(
                "No provider detail information."
                "Perhaps service has not been created")
        provider_service_id = provider_detail.provider_service_id
        return ext.obj.service_controller.delete(project_id,
                                                 provider_service_id)

    def purge(self, ext, service_obj, provider_details,
              hard=False, purge_url=None):
        """Purge a service.

        :param ext:
        :type ext: object

        :param service_obj: The service details to purge
        :type service_obj: dict

        :param provider_details: The provider details
        :type provider_details: dict

        :param hard: (Default False) Provider will be set to status
           'update_in_progress' if set to True
        :type hard: bool

        :param purge_url: The purge url
        :type purge_url: str

        :raise: BadProviderDetail if service has not been created
        """
        try:
            provider_detail = provider_details[ext.obj.provider_name]
        except KeyError:
            raise errors.BadProviderDetail(
                "No provider detail information."
                "Perhaps service has not been created")
        provider_service_id = provider_detail.provider_service_id
        return ext.obj.service_controller.purge(
            provider_service_id,
            service_obj,
            hard,
            purge_url)

    def create_certificate(self, ext, cert_obj, enqueue, https_upgrade):
        """Create a certificate.

        :param ext:
        :type ext: object

        :param cert_obj: The certificate details
        :type cert_obj: dict

        :param enqueue: The enqueue option
        :type enqueue: bool

        :param https_upgrade: The upgrade option to https
        :type https_upgrade: bool

        :return: ext.obj.certificate_controller.create_certificate(cert_obj,
            enqueue, https_upgrade)
        """

        return ext.obj.certificate_controller.create_certificate(
            cert_obj,
            enqueue,
            https_upgrade
        )

    def delete_certificate(self, ext, cert_obj):
        """Delete a certificate.

        :param ext:
        :type ext: object

        :param cert_obj: The certificate details
        :type cert_obj: dict

        :returns: ext.obj.service_controller.delete_certificate(cert_obj)
        """

        return ext.obj.certificate_controller.delete_certificate(cert_obj)

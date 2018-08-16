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

import abc

import six

from poppy.manager.base import controller
from poppy.manager.base import notifications
from poppy.manager.base import providers


@six.add_metaclass(abc.ABCMeta)
class ServicesControllerBase(controller.ManagerControllerBase):
    """Services controller base class."""

    def __init__(self, manager):
        super(ServicesControllerBase, self).__init__(manager)

        self.provider_wrapper = providers.ProviderWrapper()
        self.notification_wrapper = notifications.NotificationWrapper()

    @abc.abstractmethod
    def get_services(self, project_id, marker=None, limit=None):
        """Get a list of services.

        :param project_id: The project id
        :type project_id: str

        :param marker: The marker indicator
        :type marker: int

        :param limit: No of services to fetch
        :type limit: int

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get_service(self, project_id, service_id):
        """Get a service.

        :param project_id: The project id
        :type project_id: int

        :param service_id: The service id
        :type service_id: str

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def create_service(self, project_id, auth_token, service_obj):
        """Create a new service.

        :param project_id: The project id
        :type project_id: int

        :param auth_token: Token for the authorization
        :type auth_token: str

        :param service_obj: The new service details
        :type service_obj: dict

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def update_service(self, project_id, service_id,
                       auth_token, service_updates, force_update=False):
        """Update a service.

        :param project_id: The project id
        :type project_id: int

        :param service_id: The service id
        :type service_id: str

        :param auth_token: Token for the authorization
        :type auth_token: str

        :param service_updates: To be updated details
        :type service_updates: dict

        :param force_update: (Default False) Force update
        :type force_update: bool

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def services_action(self, project_id, action, domain=None):
        """Perform an action on services.

        :param project_id: The project id
        :type project_id: int

        :param action: Choose from 'delete', 'enable', 'disable'
        :type action: str

        :param domain: The domain name
        :type domain: str

        :raise: ValueError
        """

    @abc.abstractmethod
    def delete_service(self, project_id, service_id):
        """Delete a service.

       :param project_id: The project id
       :type project_id: int

       :param service_id: The service id
       :type service_id: str

       :raise: NotImplementedError
       """
        raise NotImplementedError

    @abc.abstractmethod
    def purge(self, project_id, service_id, hard=False, purge_url=None):
        """Purge assets for a service.

        If purge_url is none, all content of this service will be purged.

        :param project_id: The project id
        :type project_id: int

        :param service_id: The service id
        :type service_id: str

        :param hard: (Default False) Changes provider's status to
          'update_in_progress' if True

        :param purge_url: The purge URL
        :type purge_url: str

        :raise: NotImplementedError
        """
        raise NotImplementedError

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


@six.add_metaclass(abc.ABCMeta)
class FlavorsControllerBase(controller.ManagerControllerBase):
    """Flavor controller base class."""

    def __init__(self, manager):
        super(FlavorsControllerBase, self).__init__(manager)

        self._storage = self.driver.storage.flavors_controller
        self._providers = self.driver.providers

    @property
    def storage(self):
        """Return StorageController for this FlavorController.

        :return: The storage object
        """
        return self._storage

    @property
    def providers(self):
        """Get list of providers for this FlavorController.

        :return: The list of provider drivers
        """
        return self._providers

    @abc.abstractmethod
    def list(self):
        """Get list of the supported flavors.

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def get(self, flavor_id):
        """Get Flavor details for the given flavor id

        :param flavor_id: Flavor id to get the flavor details
        :type flavor_id: str

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def add(self, flavor):
        """Add a new flavor.

        :param flavor: Flavor details
        :type flavor: poppy.model.flavor.Flavor

        :raise: NotImplementedError
        """
        raise NotImplementedError

    @abc.abstractmethod
    def delete(self, flavor_id, provider_id):
        """Delete a flavor.

        :param flavor_id: The flavor id to delete
        :type flavor_id: str

        :param provider_id: The provider id of the flavor
        :type provider_id: str

        :raise: NotImplementedError
        """
        raise NotImplementedError

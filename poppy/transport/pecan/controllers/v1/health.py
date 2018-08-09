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

import pecan
from pecan import hooks

from poppy.transport.pecan.controllers import base
from poppy.transport.pecan import hooks as poppy_hooks
from poppy.transport.pecan.models.response import health as health_response


class DNSHealthController(base.Controller, hooks.HookController):

    __hooks__ = [poppy_hooks.Context(), poppy_hooks.Error()]

    """DNS Health Controller."""

    @pecan.expose('json')
    def get(self, dns_name):
        """

        Returns the health of DNS Provider
        :type dns_name: str
        :param dns_name: Name of the DNS
        :return: JSON dns model or HTTP 404
        :rtype: collections.OrderedDict
        """
        health_controller = self._driver.manager.health_controller

        try:
            is_alive = health_controller.is_dns_alive(dns_name)
            return health_response.DNSModel(is_alive)
        except KeyError:
            pecan.response.status = 404


class StorageHealthController(base.Controller, hooks.HookController):

    __hooks__ = [poppy_hooks.Context(), poppy_hooks.Error()]

    """Storage Health Controller."""

    @pecan.expose('json')
    def get(self, storage_name):
        """

        Returns the health of storage
        :type storage_name: str
        :param storage_name: Name of the storage
        :return: JSON storage model or HTTP 404
        :rtype: collections.OrderedDict
        """
        health_controller = self._driver.manager.health_controller

        try:
            is_alive = health_controller.is_storage_alive(storage_name)
            return health_response.StorageModel(is_alive)
        except KeyError:
            pecan.response.status = 404


class DistributedTaskHealthController(base.Controller, hooks.HookController):

    __hooks__ = [poppy_hooks.Context(), poppy_hooks.Error()]

    """Distributed Task Health Controller."""

    @pecan.expose('json')
    def get(self, distributed_task_name):
        """

        Returns the health of distributed task manager
        :type distributed_task_name: str
        :param distributed_task_name: Name of the distributed task
        :return: JSON Distributed task model  or HTTP 404
        :rtype: collections.OrderedDict
        """
        health_controller = self._driver.manager.health_controller

        try:
            is_alive = health_controller.is_distributed_task_alive(
                distributed_task_name)
            return health_response.DistributedTaskModel(is_alive)
        except KeyError:
            pecan.response.status = 404


class ProviderHealthController(base.Controller, hooks.HookController):

    __hooks__ = [poppy_hooks.Context(), poppy_hooks.Error()]

    @pecan.expose('json')
    def get(self, provider_name):
        """

        Returns the health of provider
        :type provider_name: str
        :param provider_name: Name of the provider
        :return: JSON provider model or HTTP 404
        :rtype: collections.OrderedDict
        """


        health_controller = self._driver.manager.health_controller

        try:
            is_alive = health_controller.is_provider_alive(provider_name)
            return health_response.ProviderModel(is_alive)
        except KeyError:
            pecan.response.status = 404


class HealthController(base.Controller, hooks.HookController):

    __hooks__ = [poppy_hooks.Context(), poppy_hooks.Error()]

    @pecan.expose('json')
    def get(self):
        """
        Returns the health of storage and providers
        :return: JSON response or HTTP 503
        :rtype: collections.OrderedDict
        """


        health_controller = self._driver.manager.health_controller

        is_alive, health_map = health_controller.health()
        if not is_alive:
            pecan.response.status = 503

        return health_response.HealthModel(self, health_map)

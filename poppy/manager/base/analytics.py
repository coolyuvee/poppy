# Copyright (c) 2016 Rackspace, Inc.
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
class AnalyticsController(controller.ManagerControllerBase):
    """Home controller base class."""

    def __init__(self, manager):
        self.manager = manager
        super(AnalyticsController, self).__init__(manager)

    @property
    def storage_controller(self):
        """Return storage controller.

        :return:  Storage controller
        :rtype: poppy.storage.cassandra.services.ServicesController
        """
        return self.manager.storage.services_controller

    @property
    def providers(self):
        """Return provider module.

        :return: Provider module
        :rtype: poppy.provider.akamai
        """
        return self.manager.providers

    @property
    def metrics_controller(self):
        """Return metrics controller.

        :return:  Metrics controller
        :rtype: poppy.metrics.blueflood.services.ServicesController
        """
        return self.manager.metrics.services_controller

    @abc.abstractmethod
    def get_metrics_by_domain(self, project_id, domain_name, **extras):
        """Get analytics metrics by domain.

       :param project_id: The project id
       :type project_id: int

       :param domain_name: The domain name
       :type domain_name: str

       :raises: NotImplementedError
       """
        raise NotImplementedError

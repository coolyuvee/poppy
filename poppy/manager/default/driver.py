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

"""Default manager driver implementation."""

from poppy.common import decorators
from poppy.manager import base
from poppy.manager.default import controllers


class DefaultManagerDriver(base.Driver):
    """Default Manager Driver."""

    def __init__(self, conf, storage, providers, dns, distributed_task,
                 notification, metrics):
        super(DefaultManagerDriver, self).__init__(
            conf, storage, providers, dns, distributed_task, notification,
            metrics)

    @decorators.lazy_property(write=True)
    def analytics_controller(self):
        """Return the driver's analytics controller.

        :return: Analytics controller
        :rtype: poppy.manager.default.analytics.AnalyticsController
        """
        return controllers.Analytics(self)

    @decorators.lazy_property(write=True)
    def services_controller(self):
        """Return the driver's services controller.

        :return: Services controller
        :rtype: poppy.manager.default.services.DefaultServiceController
        """

        return controllers.Services(self)

    @decorators.lazy_property(write=False)
    def home_controller(self):
        """Return the driver's home controller.

        :return: Home controller
        :rtype: poppy.manager.default.home.DefaultHomeController
        """

        return controllers.Home(self)

    @decorators.lazy_property(write=False)
    def flavors_controller(self):
        """Return the driver's flavors controller.

        :return: Flavors controller
        :rtype: poppy.manager.default.flavors.DefaultFlavorsController
        """

        return controllers.Flavors(self)

    @decorators.lazy_property(write=False)
    def health_controller(self):
        """Return the driver's health controller.

        :return: Health controller
        :rtype: poppy.manager.default.health.DefaultHealthController
        """

        return controllers.Health(self)

    @decorators.lazy_property(write=False)
    def background_job_controller(self):
        """Return the driver's background controller.

        :return: Background Job controller
        :rtype: poppy.manager.default.background_job.BackgroundJobController
        """

        return controllers.BackgroundJob(self)

    @decorators.lazy_property(write=False)
    def ssl_certificate_controller(self):
        """Return the driver's SSL Certificate controller.

        :return: SSL Certificate controller
        :rtype: poppy.manager.default.ssl_certificate.DefaultSSLCertificateController
        """

        return controllers.SSLCertificate(self)

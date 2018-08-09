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

try:
    import ordereddict as collections
except ImportError:        # pragma: no cover
    import collections     # pragma: no cover


class Model(collections.OrderedDict):

    """
    Serialize a log_delivery object into an OrderedDict.
    Can be used to send the service details back to client.

    Example :
        from poppy.model import log_delivery
        from poppy.transport.pecan.models.response import log_delivery as log_delivery_response
        log_delivery_obj = log_delivery.LogDelivery()
        return log_delivery_response.Model(log_delivery_obj, self)

    """

    def __init__(self, log_delivery):
        super(Model, self).__init__()
        self['enabled'] = log_delivery.enabled

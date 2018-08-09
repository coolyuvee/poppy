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
try:
    import ordereddict as collections
except ImportError:        # pragma: no cover
    import collections     # pragma: no cover

from poppy.common import util
from poppy.transport.pecan.models.response import rule


class Model(collections.OrderedDict):
    """

    Serialize an Origin object into an OrderedDict.
    Can be used to send the service details back to client.

    Example :
        from poppy.model.helpers import origin
        from poppy.transport.pecan.models.response import origin as origin_response
        origin_response_obj = origin.Origin('origin')
        return origin_response.Model(origin_response_obj, self)

    """


    def __init__(self, origin):
        super(Model, self).__init__()
        self['origin'] = util.help_escape(origin.origin)
        self['port'] = origin.port
        self['ssl'] = origin.ssl
        self['rules'] = [rule.Model(r) for r in origin.rules]
        self['hostheadertype'] = origin.hostheadertype
        if origin.hostheadervalue is not None:
            self['hostheadervalue'] = origin.hostheadervalue

/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openvpp.jvpp.dto;

import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.VppInvocationException;

/**
* Base interface for all request DTOs
*/
public interface JVppRequest {

    /**
     * Invoke current operation asynchronously on VPP
     *
     * @return context id of this request. Can be used to track incoming response
     */
    int send(JVpp jvpp) throws VppInvocationException;

}

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

package org.openvpp.jvpp.core.test;

import java.util.Objects;
import java.util.concurrent.Future;
import java.util.concurrent.CompletionStage;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.openvpp.jvpp.JVpp;
import org.openvpp.jvpp.JVppRegistry;
import org.openvpp.jvpp.JVppRegistryImpl;
import org.openvpp.jvpp.core.JVppCoreImpl;
import org.openvpp.jvpp.core.dto.GetNodeIndex;
import org.openvpp.jvpp.core.dto.GetNodeIndexReply;
import org.openvpp.jvpp.core.dto.ShowVersion;
import org.openvpp.jvpp.core.dto.ShowVersionReply;
import org.openvpp.jvpp.core.dto.SwInterfaceDetails;
import org.openvpp.jvpp.core.dto.SwInterfaceDetailsReplyDump;
import org.openvpp.jvpp.core.dto.SwInterfaceDump;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64Add;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64AddReply;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64Del;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64DelReply;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64SyncEnable;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64SyncEnableReply;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64SyncDisable;
import org.openvpp.jvpp.core.dto.SwInterfaceFip64SyncDisableReply;
import org.openvpp.jvpp.core.future.FutureJVppCoreFacade;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(FutureApiTest.class.getName());

    private static SwInterfaceFip64Add createFip64AddRequest(Byte fip64Id, int vrf) {
        SwInterfaceFip64Add request = new SwInterfaceFip64Add();
        request.fip6 = new byte[] {0x20,1,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,fip64Id}; // 2001::
        request.fixed4 = new byte[] {40,30,20,10}; // 40.30.20.10
        request.poolStart = new byte[] {10,0,0,1}; // 10.0.0.1
        request.poolEnd = new byte[] {10,0,2,2}; // 10.0.2.2
        request.tableId = vrf;
        request.vni = 0xffffff00; // vni 0xffffff on little endian machine
        return request;
    }

    private static void testShowVersion(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending ShowVersion request...");
        final Future<ShowVersionReply> replyFuture = jvpp.showVersion(new ShowVersion()).toCompletableFuture();
        final ShowVersionReply reply = replyFuture.get();
        LOG.info(
            String.format(
                "Received ShowVersionReply: context=%d, program=%s, version=%s, buildDate=%s, buildDirectory=%s\n",
                reply.context, new String(reply.program), new String(reply.version), new String(reply.buildDate),
                new String(reply.buildDirectory)));
    }

    private static void testGetNodeIndex(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending GetNodeIndex request...");
        final GetNodeIndex request = new GetNodeIndex();
        request.nodeName = "ip6-fip64".getBytes();
        final Future<GetNodeIndexReply> replyFuture = jvpp.getNodeIndex(request).toCompletableFuture();
        final GetNodeIndexReply reply = replyFuture.get();
        LOG.info(
            String.format(
                "Received GetNodeIndexReply: context=%d, nodeIndex=%d\n", reply.context, reply.nodeIndex));
    }

    private static void testSwInterfaceDump(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending SwInterfaceDump request...");
        final SwInterfaceDump request = new SwInterfaceDump();
        request.nameFilterValid = 0;
        request.nameFilter = "".getBytes();

        final Future<SwInterfaceDetailsReplyDump> replyFuture = jvpp.swInterfaceDump(request).toCompletableFuture();
        final SwInterfaceDetailsReplyDump reply = replyFuture.get();
        for (SwInterfaceDetails details : reply.swInterfaceDetails) {
            Objects.requireNonNull(details, "reply.swInterfaceDetails contains null element!");
            LOG.info(
                String.format("Received SwInterfaceDetails: interfaceName=%s, l2AddressLength=%d, adminUpDown=%d, "
                        + "linkUpDown=%d, linkSpeed=%d, linkMtu=%d\n",
                    new String(details.interfaceName), details.l2AddressLength, details.adminUpDown,
                    details.linkUpDown, details.linkSpeed, (int) details.linkMtu));
        }
    }

    // Check that Fip64Add method completes successfully
    private static void testFip64Add(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64Add request...");
        SwInterfaceFip64Add request = createFip64AddRequest((byte)1, 0x01000000); // vrf = 1
        final Future<SwInterfaceFip64AddReply> replyFuture =
            jvpp.swInterfaceFip64Add(request).toCompletableFuture();
        final SwInterfaceFip64AddReply reply = replyFuture.get();
        LOG.info("OK");
    }

    // Check that Fip64Del method throws an exeption if given fip6 does not exist
    private static void testFip64Del(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64Del request...");

        SwInterfaceFip64Del request = new SwInterfaceFip64Del();
        request.fip6 = new byte[] {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
        try {
            final Future<SwInterfaceFip64DelReply> replyFuture =
                jvpp.swInterfaceFip64Del(request).toCompletableFuture();
            final SwInterfaceFip64DelReply reply = replyFuture.get();
            throw new Exception("Fip64Del request failed");
        } catch (Exception evpp) {
            LOG.log(Level.INFO, "Expected exception", evpp);
            LOG.info("OK");
        }
    }

    // Check that Fip64Add/Fip64Del works
    private static void testFip64AddDel(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64Add request...");
        SwInterfaceFip64Add request = createFip64AddRequest((byte)2, 0x02000000); // vrf = 2
        final Future<SwInterfaceFip64AddReply> replyFuture =
            jvpp.swInterfaceFip64Add(request).toCompletableFuture();
        final SwInterfaceFip64AddReply reply = replyFuture.get();
        SwInterfaceFip64Del delRequest = new SwInterfaceFip64Del();
        delRequest.fip6 = request.fip6;
        final Future<SwInterfaceFip64DelReply> replyFuture1 =
            jvpp.swInterfaceFip64Del(delRequest).toCompletableFuture();
        final SwInterfaceFip64DelReply delReply = replyFuture1.get();
        LOG.info("OK");
    }

    // Check that Fip64SyncEnable method completes successfully
    private static void testFip64SyncEnable(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64SyncEnable request...");
        SwInterfaceFip64SyncEnable request = new SwInterfaceFip64SyncEnable();
        request.vrfId = 0x01000000;
        final Future<SwInterfaceFip64SyncEnableReply> replyFuture =
            jvpp.swInterfaceFip64SyncEnable(request).toCompletableFuture();
        final SwInterfaceFip64SyncEnableReply reply = replyFuture.get();
        LOG.info("OK");
    }

    // Check that Fip64SyncDisable method throws an exeption if sync is disabled
    private static void testFip64SyncDisable(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64SyncDisable request...");

        SwInterfaceFip64SyncDisable request = new SwInterfaceFip64SyncDisable();
        try {
            final Future<SwInterfaceFip64SyncDisableReply> replyFuture =
                jvpp.swInterfaceFip64SyncDisable(request).toCompletableFuture();
            final SwInterfaceFip64SyncDisableReply reply = replyFuture.get();
            throw new Exception("Fip64SyncDisable request failed");
        } catch (Exception evpp) {
            LOG.log(Level.INFO, "Expected exception", evpp);
            LOG.info("OK");
        }
    }

    // Check that Fip64SyncEnable/Fip64SyncDisable works
    private static void testFip64SyncEnableDisable(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64SyncEnable request...");
        SwInterfaceFip64SyncEnable request = new SwInterfaceFip64SyncEnable();
        request.vrfId = 0x02000000; // vrfId = 2
        final Future<SwInterfaceFip64SyncEnableReply> replyFuture =
            jvpp.swInterfaceFip64SyncEnable(request).toCompletableFuture();
        final SwInterfaceFip64SyncEnableReply reply = replyFuture.get();
        SwInterfaceFip64SyncDisable delRequest = new SwInterfaceFip64SyncDisable();
        final Future<SwInterfaceFip64SyncDisableReply> replyFuture1 =
          jvpp.swInterfaceFip64SyncDisable(delRequest).toCompletableFuture();
        final SwInterfaceFip64SyncDisableReply delReply = replyFuture1.get();
        LOG.info("OK");
    }

    private static void testFutureApi() throws Exception {
        LOG.info("Testing Java future API");

        final JVppRegistry registry = new JVppRegistryImpl("FutureApiTest");
        final JVpp jvpp = new JVppCoreImpl();
        final FutureJVppCoreFacade jvppFacade = new FutureJVppCoreFacade(registry, jvpp);
        LOG.info("Successfully connected to VPP");

        try {
            testShowVersion(jvppFacade);
            testGetNodeIndex(jvppFacade);
            testSwInterfaceDump(jvppFacade);
            testFip64Add(jvppFacade);
            testFip64Del(jvppFacade);
            testFip64AddDel(jvppFacade);
            testFip64SyncEnable(jvppFacade);
            testFip64SyncDisable(jvppFacade);
            testFip64SyncEnableDisable(jvppFacade);
            LOG.info("ALL PASSED");
        } catch (Exception e) {
            LOG.log(Level.SEVERE, e.toString());
        } finally {
            LOG.info("Disconnecting...");
            registry.close();
        }
    }

    public static void main(String[] args) throws Exception {
        testFutureApi();
    }
}

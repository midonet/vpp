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
import org.openvpp.jvpp.core.dto.Fip64Add;
import org.openvpp.jvpp.core.dto.Fip64AddReply;
import org.openvpp.jvpp.core.dto.Fip64Del;
import org.openvpp.jvpp.core.dto.Fip64DelReply;
import org.openvpp.jvpp.core.dto.Fip64SyncEnable;
import org.openvpp.jvpp.core.dto.Fip64SyncEnableReply;
import org.openvpp.jvpp.core.dto.Fip64SyncDisable;
import org.openvpp.jvpp.core.dto.Fip64SyncDisableReply;
import org.openvpp.jvpp.core.future.FutureJVppCoreFacade;

public class FutureApiTest {

    private static final Logger LOG = Logger.getLogger(FutureApiTest.class.getName());

    private static Fip64Add createFip64AddRequest(Byte fip64Id, int vrf) {
        Fip64Add request = new Fip64Add();
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
        Fip64Add request = createFip64AddRequest((byte)1, 0x01000000); // vrf = 1
        final Future<Fip64AddReply> replyFuture =
            jvpp.fip64Add(request).toCompletableFuture();
        final Fip64AddReply reply = replyFuture.get();
        LOG.info("OK");
    }

    // Check that Fip64Del method throws an exeption if given fip6 does not exist
    private static void testFip64Del(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64Del request...");

        Fip64Del request = new Fip64Del();
        request.fip6 = new byte[] {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
        try {
            final Future<Fip64DelReply> replyFuture =
                jvpp.fip64Del(request).toCompletableFuture();
            final Fip64DelReply reply = replyFuture.get();
            throw new Exception("Fip64Del successed for non-existing fip6");
        } catch (Exception evpp) {
            LOG.log(Level.INFO, "Expected exception", evpp);
            LOG.info("OK");
        }
    }

    // Check that Fip64Add/Fip64Del works
    private static void testFip64AddDel(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64Add request...");
        Fip64Add request = createFip64AddRequest((byte)2, 0x02000000); // vrf = 2
        final Future<Fip64AddReply> replyFuture =
            jvpp.fip64Add(request).toCompletableFuture();
        final Fip64AddReply reply = replyFuture.get();
        Fip64Del delRequest = new Fip64Del();
        delRequest.fip6 = request.fip6;
        LOG.info("Sending Fip64Del request...");
        final Future<Fip64DelReply> replyFuture1 =
            jvpp.fip64Del(delRequest).toCompletableFuture();
        final Fip64DelReply delReply = replyFuture1.get();
        LOG.info("OK");
    }

    // Check that Fip64SyncEnable method completes successfully
    private static void testFip64SyncEnable(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64SyncEnable request...");
        Fip64SyncEnable request = new Fip64SyncEnable();
        request.vrfId = 0x01000000;
        final Future<Fip64SyncEnableReply> replyFuture =
            jvpp.fip64SyncEnable(request).toCompletableFuture();
        final Fip64SyncEnableReply reply = replyFuture.get();
        LOG.info("OK");
    }

    // Check that Fip64SyncDisable method throws an exeption if sync is disabled
    private static void testFip64SyncDisable(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64SyncDisable request...");

        Fip64SyncDisable request = new Fip64SyncDisable();
        try {
            final Future<Fip64SyncDisableReply> replyFuture =
                jvpp.fip64SyncDisable(request).toCompletableFuture();
            final Fip64SyncDisableReply reply = replyFuture.get();
            throw new Exception("Fip64SyncDisable successed but Sync had not been enabled");
        } catch (Exception evpp) {
            LOG.log(Level.INFO, "Expected exception", evpp);
            LOG.info("OK");
        }
    }

    // Check that Fip64SyncEnable/Fip64SyncDisable works
    private static void testFip64SyncEnableDisable(final FutureJVppCoreFacade jvpp) throws Exception {
        LOG.info("Sending Fip64SyncEnable request...");
        Fip64SyncEnable request = new Fip64SyncEnable();
        request.vrfId = 0x02000000; // vrfId = 2
        final Future<Fip64SyncEnableReply> replyFuture =
            jvpp.fip64SyncEnable(request).toCompletableFuture();
        final Fip64SyncEnableReply reply = replyFuture.get();
        Fip64SyncDisable delRequest = new Fip64SyncDisable();
        LOG.info("Sending Fip64SyncDisable request...");
        final Future<Fip64SyncDisableReply> replyFuture1 =
          jvpp.fip64SyncDisable(delRequest).toCompletableFuture();
        final Fip64SyncDisableReply delReply = replyFuture1.get();
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

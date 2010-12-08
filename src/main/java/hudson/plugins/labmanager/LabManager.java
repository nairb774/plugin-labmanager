/**
 *  Copyright (C) 2010 Mentor Graphics Corporation
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Based on the libvirt-plugin which is:
 *  Copyright (C) 2010, Byte-Code srl <http://www.byte-code.com>
 *
 * Date: Mar 04, 2010
 * Author: Marco Mornati<mmornati@byte-code.com>
 */
package hudson.plugins.labmanager;

import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Label;
import hudson.slaves.Cloud;
import hudson.slaves.NodeProvisioner;
import hudson.util.FormValidation;
import hudson.util.Scrambler;

import java.io.IOException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import net.sf.json.JSONObject;

import org.apache.axis2.client.Options;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;

import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.ArrayOfMachine;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.AuthenticationHeader;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.AuthenticationHeaderE;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.GetSingleConfigurationByName;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.GetSingleConfigurationByNameResponse;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.ListMachines;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.ListMachinesResponse;
import com.vmware.labmanager.LabManager_x0020_SOAP_x0020_interfaceStub.Machine;

/**
 * Represents a virtual Lab Manager Organization/Workspace/Configuration
 * combination.
 *
 * @author Tom Rini <tom_rini@mentor.com>
 */
public class LabManager extends Cloud {
    private static final Logger LOGGER = Logger.getLogger(LabManager.class.getName());
    private final String lmHost;
    private final String lmDescription;
    private final String lmOrganization;
    private final String lmWorkspace;
    private final String lmConfiguration;
    private final String username;
    private final String password;
    private final boolean insecureSsl;

    /**
     * Information to connect to Lab Manager and send SOAP requests.
     */
    private AuthenticationHeaderE lmAuth = null;

    /**
     * Lazily computed list of virtual machines in this configuration.
     */
    private transient List<LabManagerVirtualMachine> virtualMachineList = null;

    @DataBoundConstructor
    public LabManager(String lmHost, String lmDescription,
                    String lmOrganization, String lmWorkspace,
                    String lmConfiguration, String username,
                    String password, boolean insecureSsl) {
        super("LabManager");
        this.lmHost = lmHost;
        this.lmDescription = lmDescription;
        this.lmOrganization = lmOrganization;
        if (lmWorkspace.length() != 0)
            this.lmWorkspace = lmWorkspace;
        else
            this.lmWorkspace = "main";
        this.lmConfiguration = lmConfiguration;
        this.username = username;
        this.password = Scrambler.scramble(Util.fixEmptyAndTrim(password));
        /* Setup our auth token. */
        AuthenticationHeader ah = new AuthenticationHeader();
        ah.setUsername(username);
        ah.setPassword(password);
        this.lmAuth = new AuthenticationHeaderE();
        this.lmAuth.setAuthenticationHeader(ah);
        virtualMachineList = retrieveLabManagerVirtualMachines();
        this.insecureSsl = insecureSsl;
    }

    public String getLmHost() {
        return lmHost;
    }

    public String getLmDescription() {
        return lmDescription;
    }

    public String getLmOrganization() {
        return lmOrganization;
    }

    public String getLmWorkspace() {
        return lmWorkspace;
    }

    public String getLmConfiguration() {
        return lmConfiguration;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return Scrambler.descramble(password);
    }

    private static LabManager_x0020_SOAP_x0020_interfaceStub getLmStub(final String lmHost, final boolean insecureSsl) {
        LabManager_x0020_SOAP_x0020_interfaceStub lmStub = null;
        try {
            lmStub = new LabManager_x0020_SOAP_x0020_interfaceStub(lmHost + "/LabManager/SOAP/LabManager.asmx");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        if (insecureSsl) {
            try {
                final Options options = lmStub._getServiceClient().getOptions();
                if ("https".equals(new URL(options.getTo().getAddress()).getProtocol())) {
                    options.setProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER, new Protocol("https",
                            (ProtocolSocketFactory) new InsecureProtocolSocketFactory(), 443));
                }
            } catch (final KeyManagementException e) {
                LOGGER.log(Level.WARNING, "Unable to bypass SSL checking. Please check your JVM setup.", e);
            } catch (final NoSuchAlgorithmException e) {
                LOGGER.log(Level.WARNING, "Unable to bypass SSL checking. Please check your JVM setup.", e);
            } catch (final MalformedURLException e) {
                LOGGER.log(Level.WARNING, "The url to the lab manager endpoint seems to be malformed. "
                        + "Please check your configuration.", e);
            }
        }

        return lmStub;
    }
    
    public LabManager_x0020_SOAP_x0020_interfaceStub getLmStub() {
        return getLmStub(lmHost, insecureSsl);
    }

    public AuthenticationHeaderE getLmAuth() {
        return lmAuth;
    }

    private List<LabManagerVirtualMachine> retrieveLabManagerVirtualMachines() {
        LabManager_x0020_SOAP_x0020_interfaceStub lmStub = getLmStub();
        List<LabManagerVirtualMachine> vmList = new ArrayList<LabManagerVirtualMachine>();
        /* Get the list of machines.  We do this by asking for our
         * configuration and then passing that ID to a request for
         * listMachines.
         */
        try {
            GetSingleConfigurationByName gscbnReq = new GetSingleConfigurationByName();
            gscbnReq.setName(lmConfiguration);
            GetSingleConfigurationByNameResponse gscbnResp = lmStub.getSingleConfigurationByName(gscbnReq, lmAuth);
            ListMachines lmReq = new ListMachines();
            lmReq.setConfigurationId(gscbnResp.getGetSingleConfigurationByNameResult().getId());
            ListMachinesResponse lmResp = lmStub.listMachines(lmReq, lmAuth);

            ArrayOfMachine aom = lmResp.getListMachinesResult();
            for (Machine mach : aom.getMachine())
                vmList.add(new LabManagerVirtualMachine(this, mach.getName()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return vmList;
    }

    public synchronized List<LabManagerVirtualMachine> getLabManagerVirtualMachines() {
        if (virtualMachineList == null) {
            virtualMachineList = retrieveLabManagerVirtualMachines();
        }
        return virtualMachineList;
    }

    public Collection<NodeProvisioner.PlannedNode> provision(Label label, int i) {
        return Collections.emptySet();
    }

    public boolean canProvision(Label label) {
        return false;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder();
        sb.append("LabManager");
        sb.append("{Host='").append(lmHost).append('\'');
        sb.append(", Description='").append(lmDescription).append('\'');
        sb.append(", Organization='").append(lmOrganization).append('\'');
        sb.append(", Workspace='").append(lmWorkspace).append('\'');
        sb.append(", Configuration='").append(lmConfiguration).append('\'');
        sb.append('}');
        return sb.toString();
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<Cloud> {
        public final ConcurrentMap<String, LabManager> hypervisors = new ConcurrentHashMap<String, LabManager>();
        private String lmHost;
        private String lmOrganization;
        private String lmWorkspace;
        private String lmConfiguration;
        private String username;
        private String password;

        @Override
        public String getDisplayName() {
            return "Lab Manager";
        }

        @Override
        public boolean configure(StaplerRequest req, JSONObject o)
                throws FormException {
            lmHost = o.getString("lmHost");
            lmOrganization = o.getString("lmOrganization");
            lmWorkspace = o.getString("lmWorkspace");
            lmConfiguration = o.getString("lmConfiguration");
            username = o.getString("username");
            password = o.getString("password");
            save();
            return super.configure(req, o);
        }

        /**
         * For UI.
         */
        public FormValidation doTestConnection(@QueryParameter String lmHost,
                @QueryParameter String lmOrganization,
                @QueryParameter String lmDescription,
                @QueryParameter String lmWorkspace,
                @QueryParameter String lmConfiguration,
                @QueryParameter String username,
                @QueryParameter String password,
                @QueryParameter boolean insecureSsl) {
            try {
                /* We know that these objects are not null */
                if (lmHost.length() == 0)
                    return FormValidation.error("Lab Manager host is not specified");
                else {
                    /* Perform other sanity checks. */
                    if (!lmHost.startsWith("https://"))
                        return FormValidation.error("Lab Manager host must start with https://");
                }

                if (lmOrganization.length() == 0)
                    return FormValidation.error("Lab Manager organization is not specified");

                if (lmConfiguration.length() == 0)
                    return FormValidation.error("Lab Manager configuration is not specified");

                if (username.length() == 0)
                    return FormValidation.error("Username is not specified");

                if (password.length() == 0)
                    return FormValidation.error("Password is not specified");

                /* Try and connect to it. */
                LabManager_x0020_SOAP_x0020_interfaceStub stub = getLmStub(lmHost, insecureSsl);
                AuthenticationHeader ah = new AuthenticationHeader();
                ah.setUsername(username);
                ah.setPassword(password);
                AuthenticationHeaderE ahe = new AuthenticationHeaderE();
                ahe.setAuthenticationHeader(ah);

                /* GetCurrentOrganizationName */
                GetSingleConfigurationByName request = new GetSingleConfigurationByName();
                request.setName(lmConfiguration);
                GetSingleConfigurationByNameResponse resp = stub.getSingleConfigurationByName(request, ahe);
                if (lmConfiguration.equals(resp.getGetSingleConfigurationByNameResult().getName()))
                    return FormValidation.ok("Connected successfully");
                else
                    return FormValidation.error("Could not login and retrieve basic information to confirm setup");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static class InsecureProtocolSocketFactory implements SecureProtocolSocketFactory {
        private final SSLSocketFactory socketFactory;

        public InsecureProtocolSocketFactory() throws NoSuchAlgorithmException, KeyManagementException {
            final SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, new TrustManager[] { new InsecureTrustManager() }, null);
            socketFactory = context.getSocketFactory();
        }

        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort) throws IOException,
                UnknownHostException {
            return socketFactory.createSocket(host, port, localAddress, localPort);
        }

        public Socket createSocket(String host, int port, InetAddress localAddress, int localPort,
                HttpConnectionParams params) throws IOException, UnknownHostException, ConnectTimeoutException {
            return createSocket(host, port, localAddress, localPort);
        }

        public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
            return socketFactory.createSocket(host, port);
        }

        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException,
                UnknownHostException {
            return socketFactory.createSocket(socket, host, port, autoClose);
        }
    }

    private static class InsecureTrustManager implements X509TrustManager {
        public void checkClientTrusted(final X509Certificate[] chain, final String authType) {
        }

        public void checkServerTrusted(final X509Certificate[] chain, final String authType) {
        }

        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }
    }
}

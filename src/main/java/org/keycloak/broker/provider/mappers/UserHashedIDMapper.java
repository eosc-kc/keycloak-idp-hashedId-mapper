/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.broker.provider.mappers;

import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.social.bitbucket.BitbucketIdentityProviderFactory;
import org.keycloak.social.facebook.FacebookIdentityProviderFactory;
import org.keycloak.social.github.GitHubIdentityProviderFactory;
import org.keycloak.social.gitlab.GitLabIdentityProviderFactory;
import org.keycloak.social.google.GoogleIdentityProviderFactory;
import org.keycloak.social.instagram.InstagramIdentityProviderFactory;
import org.keycloak.social.linkedin.LinkedInIdentityProvider;
import org.keycloak.social.linkedin.LinkedInIdentityProviderFactory;
import org.keycloak.social.microsoft.MicrosoftIdentityProvider;
import org.keycloak.social.microsoft.MicrosoftIdentityProviderFactory;
import org.keycloak.social.openshift.OpenshiftV3IdentityProviderFactory;
import org.keycloak.social.openshift.OpenshiftV4IdentityProviderFactory;
import org.keycloak.social.paypal.PayPalIdentityProviderFactory;
import org.keycloak.social.stackoverflow.StackoverflowIdentityProviderFactory;
import org.keycloak.social.twitter.TwitterIdentityProviderFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;


public class UserHashedIDMapper extends AbstractIdentityProviderMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {ANY_PROVIDER};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();


    public static final String HASH_ID_SALT = "hash.id.salt";
    public static final String HASH_ID_SCOPE = "hash.id.scope";
    public static final String SKIP_AUTHORITY_LIST = "skip.authority.list";
    public static final String IDP_TAG_WHITELIST = "idp.tag.whitelist";
    public static final String IDP_TAG_BLACKLIST = "idp.tag.blacklist";
    public static final String USER_ATTRIBUTE = "user.attribute";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));


    static {
        ProviderConfigProperty property;

        property = new ProviderConfigProperty();
        property.setName(USER_ATTRIBUTE);
        property.setLabel("User ID Attribute Name");
        property.setHelpText("User attribute name to store the computed id (hash) for the user. Defaults to 'subject-id'");
        property.setDefaultValue("subject-id");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(HASH_ID_SALT);
        property.setLabel("Hash salt");
        property.setHelpText("Set a salt for the id hashing.  You can leave this blank if you don't want to use a salt.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(HASH_ID_SCOPE);
        property.setLabel("Append a scope");
        property.setHelpText("Append a @scope value. You can leave this blank if you don't want to append a scope value.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        //TODO: enable these options in a future release
        /*
        property = new ProviderConfigProperty();
        property.setName(SKIP_AUTHORITY_LIST);
        property.setLabel("Skip authorities list");
        property.setHelpText("A comma ',' delimited list of IdP entityIDs that should be excluded from the authority part of the user id source. Leave empty to disable.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(IDP_TAG_WHITELIST);
        property.setLabel("IdP tag whitelist");
        property.setHelpText("A comma ',' delimited list of tags that the auth process should be executed. Leave empty to disable.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(IDP_TAG_BLACKLIST);
        property.setLabel("IdP tag blacklist");
        property.setHelpText("A comma ',' delimited list of tags that the auth process should not be executed. Leave empty to disable.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        */

    }

    public static final String PROVIDER_ID = "user-hashedid-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Hashed User ID Mapper";
    }

    @Override
    public String getDisplayType() {
        return "Hashed User ID Mapper";
    }


    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {

        //the id should be computed as:  SHA-256(AttributeValue!AuthenticatingAuthority!SecretSalt)@scope

        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        String entityId = assertion.getIssuer().getValue(); //authenticating authority

        String attributeValue = context.getId();

        String salt = mapperModel.getConfig().get(HASH_ID_SALT);
        String scope = mapperModel.getConfig().get(HASH_ID_SCOPE);

        String identifier = attributeValue + "!" + entityId;
        if(salt!=null && !salt.isEmpty())
            identifier += ("!" + salt);

        identifier = getHash(identifier);

        if(scope!=null && !scope.isEmpty())
            identifier += ("@" + scope);


        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        context.setUserAttribute(attribute, identifier);

    }



    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        //TODO: find out a smart way to update the UserModel from any subsequent login where some of the saml response attributes (inside the context) have changed for the user
    }

    @Override
    public String getHelpText() {
        return "Generate a new saml attribute to be used as a user identifier.";
    }


    private static String getHash(String str) {
        byte[] hashBytes;
        try {
            hashBytes = MessageDigest.getInstance("SHA-256").digest(str.getBytes());
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        StringBuilder sb = new StringBuilder();
        for(byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}

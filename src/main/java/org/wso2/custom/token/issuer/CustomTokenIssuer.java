/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.custom.token.issuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OauthTokenIssuerImpl;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.List;
import java.util.Optional;

/**
 * Custom OAuth Token Issuer implementation that extends OauthTokenIssuerImpl.
 * This class can be used to customize token generation logic in WSO2 Identity Server.
 */
public class CustomTokenIssuer extends OauthTokenIssuerImpl {

    private static final Log log = LogFactory.getLog(CustomTokenIssuer.class);
    private static final String EXPIRY_TIME_PARAM = "expiry_time";

    /**
     * Issue access token using the provided token request message context.
     * This method can be overridden to customize the access token generation logic.
     *
     * @param tokReqMsgCtx OAuth token request message context
     * @return Generated access token
     * @throws OAuthSystemException if an error occurs during token generation
     */
    @Override
    public String accessToken(OAuthTokenReqMessageContext tokReqMsgCtx) throws OAuthSystemException {

        List<RequestParameter> requestParams =
                List.of(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters());
        Optional<RequestParameter> expiryTimeParam = requestParams.stream().filter(
                param -> EXPIRY_TIME_PARAM.equals(param.getKey()) && param.getValue()[0] != null).findFirst();

        if (expiryTimeParam.isPresent()) {
            try {
                long expiryTime = Long.parseLong(expiryTimeParam.get().getValue()[0]) * 1000;
                tokReqMsgCtx.setValidityPeriod(expiryTime);
                if (log.isDebugEnabled()) {
                    log.debug("Custom expiry time set to: " + expiryTime + " seconds");
                }
            } catch (NumberFormatException e) {
                log.warn("Invalid expiry time format: " + expiryTimeParam.get().getValue()[0]
                        + ". Using default validity period.");
            }
        }

        // Call the parent implementation to generate the access token
        return super.accessToken(tokReqMsgCtx);
    }
}


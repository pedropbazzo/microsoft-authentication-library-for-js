/*
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

import { StringUtils } from "./../utils/StringUtils";
import { ClientConfigurationError } from "./../error/ClientConfigurationError";
import { PromptValue, CodeChallengeMethodValues, BlacklistedEQParams, SSOTypes } from "./../utils/Constants";
import { StringDict } from "../utils/MsalTypes";

/**
 * Validates server consumable params from the "request" objects
 */
export class RequestValidator {

    /**
     * Utility to check if the `redirectUri` in the request is a non-null value
     * @param redirectUri
     */
    static validateRedirectUri(redirectUri: string) : void {
        if (StringUtils.isEmpty(redirectUri)) {
            throw ClientConfigurationError.createRedirectUriEmptyError();
        }
    }

    /**
     * Utility to validate prompt sent by the user in the request
     * @param prompt
     */
    static validatePrompt(prompt: string) : void {
        if (
            [
                PromptValue.LOGIN,
                PromptValue.SELECT_ACCOUNT,
                PromptValue.CONSENT,
                PromptValue.NONE
            ].indexOf(prompt) < 0
        ) {
            throw ClientConfigurationError.createInvalidPromptError(prompt);
        }
    }

    /**
     * Utility to validate code_challenge and code_challenge_method
     * @param codeChallenge
     * @param codeChallengeMethod
     */
    static validateCodeChallengeParams(codeChallenge: string, codeChallengeMethod: string) : void  {
        if (!(codeChallenge && codeChallengeMethod)) {
            throw ClientConfigurationError.createInvalidCodeChallengeParamsError();
        } else {
            this.validateCodeChallengeMethod(codeChallengeMethod);
        }
    }

    /**
     * Utility to validate code_challenge_method
     * @param codeChallengeMethod
     */
    static validateCodeChallengeMethod(codeChallengeMethod: string) : void {
        if (
            [
                CodeChallengeMethodValues.PLAIN,
                CodeChallengeMethodValues.S256
            ].indexOf(codeChallengeMethod) < 0
        ) {
            throw ClientConfigurationError.createInvalidCodeChallengeMethodError();
        }
    }


    /**
     * Removes unnecessary or duplicate query parameters from extraQueryParameters
     * @param request
     */
    private sanitizeEQParams(eQParams: StringDict, ssoQueryParams: StringDict) : StringDict {
        if (!eQParams) {
            return null;
        }

        // Remove any query parameters that are blacklisted
        BlacklistedEQParams.forEach(param => {
            if (eQParams[param]) {
                // TODO: this.logger.error("Removed duplicate " + param + " from extraQueryParameters. Please use the " + param + " field in request object.");
                delete eQParams[param];
            }
        });

        // Remove any query parameters already included in SSO params
        Object.keys(ssoQueryParams).forEach(key => {
            if (eQParams[key]) {
                // TODO: this.logger.error("Removed param " + key + " from extraQueryParameters since it was already present in library query parameters.")
                delete eQParams[key];
            }

            if (key === SSOTypes.SID) {
                // TODO: this.logger.error("Removed domain hint since sid was provided.")
                delete eQParams[SSOTypes.DOMAIN_HINT];
            }
        });

        return eQParams;
    }
}

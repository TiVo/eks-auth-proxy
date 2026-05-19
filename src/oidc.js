const { getEksAuthToken, getTemporaryAwsCredentials } = require('./aws');
const {
    clientSecret,
    clientId,
    oidcIssuer,
    loginUrl,
    iamRoles,
    emailDomains,
    ignoreEmailVerification,
} = require('./config');

let passportStrategy;
let oidcConfig;
let openidClientPromise;
let openidClientPassportPromise;
// eslint-disable-next-line no-new-func
const dynamicImport = new Function('modulePath', 'return import(modulePath)');

const getOpenIdClient = async () => {
    if (openidClientPromise === undefined) {
        openidClientPromise = dynamicImport('openid-client');
    }
    return openidClientPromise;
};

const getOpenIdClientPassport = async () => {
    if (openidClientPassportPromise === undefined) {
        openidClientPassportPromise = dynamicImport('openid-client/passport');
    }
    return openidClientPassportPromise;
};

const getBasePath = () => `${loginUrl}/oauth`;
const getCallbackPath = () => `${getBasePath()}/callback`;
const getRedirectUrl = (ctx) =>
    `${ctx.protocol}://${ctx.host}${getCallbackPath()}`;

const getClient = async () => {
    if (oidcConfig !== undefined) {
        return oidcConfig;
    }

    const openidClient = await getOpenIdClient();
    oidcConfig = await openidClient.discovery(
        new URL(oidcIssuer),
        clientId,
        clientSecret,
        undefined,
        { timeout: 30 }
    );

    return oidcConfig;
};

const getAssumeRoleErrorMessage = (error, roleArn) => {
    if (error.code === 'AccessDenied') {
        return `You do not have permission to assume the role ${roleArn}`;
    }
    return `Unable to assume role ${roleArn}. Check that it is correctly configured.`;
};

const validateEmail = (userinfo) => {
    // Check that the email address domain is valid if --email-domain(s) is specified
    if (emailDomains !== undefined) {
        const validDomain = emailDomains.some((domain) =>
            userinfo.email.endsWith(`@${domain}`)
        );
        if (!validDomain) {
            return {
                emailValid: false,
                emailError: 'Your email address domain is not allowed.',
            };
        }
    }

    // Make sure the email address has been verified by the IDP
    if (!userinfo.email_verified && !ignoreEmailVerification) {
        return {
            emailValid: false,
            emailError:
                'Your email address must be verified with your identity provider before you can log in.',
        };
    }

    return { emailValid: true };
};

// Take the info returned from the OIDC provider and return a user object
// This cannot be an arrow function as we rely on `this` to be the strategy that
// calls this function
async function handleAuthenticationSuccess(req, tokenset, done) {
    let awsCredentials;
    const openidClient = await getOpenIdClient();

    const idTokenClaims = tokenset.claims ? tokenset.claims() : {};
    let userinfo = { ...idTokenClaims };

    if (tokenset.access_token !== undefined) {
        const expectedSubject =
            idTokenClaims && idTokenClaims.sub
                ? idTokenClaims.sub
                : openidClient.skipSubjectCheck;
        try {
            userinfo = await openidClient.fetchUserInfo(
                await getClient(),
                tokenset.access_token,
                expectedSubject
            );
        } catch (error) {
            return done(error);
        }
    }

    // Check the email address
    const { emailValid, emailError } = validateEmail(userinfo);
    if (!emailValid) {
        return done(null, false, { message: emailError });
    }

    // Assume the IAM role
    try {
        awsCredentials = await getTemporaryAwsCredentials(
            userinfo.email,
            tokenset.id_token,
            req.session.selectedIamRole || iamRoles[0]
        );
    } catch (e) {
        return done(null, false, {
            error: e,
            message: getAssumeRoleErrorMessage(
                e,
                req.session.selectedIamRole || iamRoles[0]
            ),
        });
    }

    // Get and set the cluster auth details
    const eksToken = getEksAuthToken(awsCredentials);
    const user = { id: userinfo.sub, ...userinfo, eksToken, awsCredentials };

    return done(null, user);
}

const getPassportStrategy = async () => {
    if (passportStrategy !== undefined) {
        return Promise.resolve(passportStrategy);
    }

    const { Strategy } = await getOpenIdClientPassport();
    const config = await getClient();

    passportStrategy = new Strategy(
        { config, scope: 'openid email', passReqToCallback: true },
        handleAuthenticationSuccess
    );

    return passportStrategy;
};

// Sets the redirect_uri dynamically based on the host and uses the `iam_role` query parameter
// to dynamically set the role to be assumed
const dynamicStrategyMiddleware = async (ctx, next) => {
    const [defaultIamRole] = iamRoles;
    const roleIndex = parseInt(ctx.query.iam_role, 10);
    if (!Number.isNaN(roleIndex)) {
        const [selectedIamRole] = iamRoles.slice(roleIndex);
        ctx.session.selectedIamRole = selectedIamRole || defaultIamRole;
    } else {
        ctx.session.selectedIamRole = defaultIamRole;
    }

    ctx.state.oidcCallbackUrl = getRedirectUrl(ctx);

    await next();
};

module.exports = {
    getClient,
    getPassportStrategy,
    getBasePath,
    getCallbackPath,
    dynamicStrategyMiddleware,
};

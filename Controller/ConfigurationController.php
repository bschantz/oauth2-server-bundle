<?php
/**
 * User: Brian Schantz
 * Date: 1/13/15
 * Time: 8:28 AM
 */

namespace OAuth2\ServerBundle\Controller;


use OAuth2\Server;
use OAuth2\Storage\PublicKeyInterface;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Validator\Constraints\Regex;

class ConfigurationController extends Controller
{
    /**
     * Returns OpenID configuration in response to request at /.well-known/openid-configuration
     *
     * @link http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
     *
     * @Route("/.well-known/openid-configuration", name="_openid_configuration")
     *
     * @param Request $request
     * @return Response
     */
    public function configurationAction(Request $request)
    {
        /** @var Server $server */
        $server = $this->get('oauth2.server');

        $configKeys = [
            /*  issuer
            REQUIRED. URL using the https scheme with no query or fragment component that the OP asserts
            as its Issuer Identifier. If Issuer discovery is supported (see Section 2), this value MUST be
            identical to the issuer value returned by WebFinger. This also MUST be identical to the iss Claim value
            in ID Tokens issued from this Issuer. */
                'issuer' => $request->getBaseUrl(),

            /* authorization_endpoint
            REQUIRED. URL of the OP's OAuth 2.0 Authorization Endpoint [OpenID.Core]. */
                'authorization_endpoint' => $this->generateUrl('_authorize_handle'),

            /* token_endpoint
            URL of the OP's OAuth 2.0 Token Endpoint [OpenID.Core]. This is REQUIRED unless only the Implicit
            Flow is used. */
                'token_endpoint' => $this->generateUrl('_token'),

            /* userinfo_endpoint
            RECOMMENDED. URL of the OP's UserInfo Endpoint [OpenID.Core]. This URL MUST use the https scheme and
            MAY contain port, path, and query parameter components. */
                'userinfo_endpoint' => $this->generateUrl('_userinfo'),

            /* jwks_uri
            REQUIRED. URL of the OP's JSON Web Key Set [JWK] document. This contains the signing key(s) the RP
            uses to validate signatures from the OP. The JWK Set MAY also contain the Server's encryption key(s),
            which are used by RPs to encrypt requests to the Server. When both signing and encryption keys are made
            available, a use (Key Use) parameter value is REQUIRED for all keys in the referenced JWK Set to indicate
            each key's intended usage. Although some algorithms allow the same key to be used for both signatures and
            encryption, doing so is NOT RECOMMENDED, as it is less secure. The JWK x5c parameter MAY be used to provide
            X.509 representations of keys provided. When used, the bare key values MUST still be present and MUST
            match those in the certificate.*/
                'jwks_uri' => $this->generateUrl('_jwk'),

            /* registration_endpoint
            RECOMMENDED. URL of the OP's Dynamic Client Registration Endpoint [OpenID.Registration].*/
                'registration_endpoint' => null,

            /* scopes_supported
            RECOMMENDED. JSON array containing a list of the OAuth 2.0 [RFC6749] scope values that this server
            supports. The server MUST support the openid scope value. Servers MAY choose not to advertise some
            supported scope values even when this parameter is used, although those defined in [OpenID.Core]
            SHOULD be listed, if supported. */
                'scopes_supported' => $this->get('oauth2.scope_manager')->findAllScopes(),

            /* response_types_supported
            REQUIRED. JSON array containing a list of the OAuth 2.0 response_type values that this OP supports. Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.*/
                'response_types_supported' => ['code', 'id_token', 'token id_token'],

            /* response_modes_supported
            OPTIONAL. JSON array containing a list of the OAuth 2.0 response_mode values that this OP
            supports, as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses].
            If omitted, the default for Dynamic OpenID Providers is ["query", "fragment"].*/
                'response_modes_supported' => ['query', 'fragment'],

            /* grant_types_supported
            OPTIONAL. JSON array containing a list of the OAuth 2.0 Grant Type values that this OP supports. Dynamic OpenID Providers MUST support the authorization_code and implicit Grant Type values and MAY support other Grant Types. If omitted, the default value is ["authorization_code", "implicit"].*/
                'grant_types_supported' => ['authorization_code', 'implicit', 'password', 'client_credentials'],

            /* subject_types_supported
            REQUIRED. JSON array containing a list of the Subject Identifier types that this OP supports. Valid
            types include pairwise and public.*/
                'subject_types_supported' => ['public'],

            /* id_token_signing_alg_values_supported
            REQUIRED. JSON array containing a list of the JWS signing algorithms (alg values) supported by
            the OP for the ID Token to encode the Claims in a JWT [JWT]. The algorithm RS256 MUST be included.
            The value none MAY be supported, but MUST NOT be used unless the Response Type used returns no ID
            Token from the Authorization Endpoint (such as when using the Authorization Code Flow).*/
                'id_token_signing_alg_values_supported' => ['RS256'],

            /* token_endpoint_auth_methods_supported
            OPTIONAL. JSON array containing a list of Client Authentication methods supported by this
            Token Endpoint. The options are client_secret_post, client_secret_basic, client_secret_jwt,
            and private_key_jwt, as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core].
            Other authentication methods MAY be defined by extensions. If omitted, the default is
            client_secret_basic -- the HTTP Basic Authentication Scheme specified in Section 2.3.1 of
            OAuth 2.0 [RFC6749].*/
            //    'token_endpoint_auth_methods_supported' => null,

            /* token_endpoint_auth_signing_alg_values_supported
            OPTIONAL. JSON array containing a list of the JWS signing algorithms (alg values) supported
             by the Token Endpoint for the signature on the JWT [JWT] used to authenticate the Client at
            the Token Endpoint for the private_key_jwt and client_secret_jwt authentication methods.
            Servers SHOULD support RS256. The value none MUST NOT be used.*/
            //    'token_endpoint_auth_signing_alg_values_supported' => null,

            /* display_values_supported
            OPTIONAL. JSON array containing a list of the display parameter values that the OpenID
            Provider supports. These values are described in Section 3.1.2.1 of OpenID Connect Core
            1.0 [OpenID.Core].*/
            //    'display_values_supported' => null,

            /* claim_types_supported
            OPTIONAL. JSON array containing a list of the Claim Types that the OpenID Provider supports.
            These Claim Types are described in Section 5.6 of OpenID Connect Core 1.0 [OpenID.Core].
            Values defined by this specification are normal, aggregated, and distributed. If omitted,
            the implementation supports only normal Claims.*/
            //    'claim_types_supported' => null,

            /* claims_supported
            RECOMMENDED. JSON array containing a list of the Claim Names of the Claims that the OpenID
            Provider MAY be able to supply values for. Note that for privacy or other reasons, this
            might not be an exhaustive list.*/
            //    'claims_supported' => null,

            /* claims_locales_supported
            OPTIONAL. Languages and scripts supported for values in Claims being returned, represented as a JSON array of BCP47 [RFC5646] language tag values. Not all languages and scripts are necessarily supported for all Claim values.*/
                'claims_locales_supported' => ['en'],

            /* ui_locales_supported
            OPTIONAL. Languages and scripts supported for the user interface, represented as a JSON array of BCP47 [RFC5646] language tag values.*/
                'ui_locales_supported' => ['en'],

            /* claims_parameter_supported
            OPTIONAL. Boolean value specifying whether the OP supports use of the claims parameter, with true indicating support. If omitted, the default value is false.*/
                'claims_parameter_supported' => false,

            /* request_parameter_supported
            OPTIONAL. Boolean value specifying whether the OP supports use of the request parameter, with true indicating support. If omitted, the default value is false.*/
                'request_parameter_supported' => false,
        ];

        return Response::create(json_encode($configKeys));
    }

    /**
     * Returns JWK document with the public key(s) used to sign tokens
     *
     * @link
     *
     * @Route("/jwk", name="_jwk")
     */
    public function jwkAction()
    {
        /** @var Server $server */
        $server = $this->container->get('oauth2.server');

        /** @var PublicKeyInterface $storage */
        $storage = $server->getStorage('public_key');

        // we have to extract the public key data from the private key
        $key_text = $storage->getPrivateKey();
        if (!$key = openssl_pkey_get_private($key_text)) {
            throw new \OAuthException('Error reading key.');
        }

        if (!$key_details = openssl_pkey_get_details($key)) {
            throw new \OAuthException('Could not retrieve key details.');
        }

        if (!$key_details['type'] == OPENSSL_KEYTYPE_RSA) {
            throw new \OAuthException('Only RSA keys are supported at this time.');
        }

        if (!isset($key_details['rsa'])
                || !isset($key_details['rsa']['n'])
                || !isset($key_details['rsa']['e'])) {
            throw new \OAuthException('Could not retrieve key details.');
        }

        $key_n = str_replace(['+', '/'], ['-', '_'], base64_encode($key_details['rsa']['n']));
        $key_e = str_replace(['+', '/'], ['-', '_'], base64_encode($key_details['rsa']['e']));

        $jwk = [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => $key_n,
            'e'   => $key_e,
        ];

        return Response::create(json_encode($jwk));

    }
}

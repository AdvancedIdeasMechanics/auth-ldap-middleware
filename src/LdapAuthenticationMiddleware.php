<?php

use Laminas\Diactoros\Response\EmptyResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Laminas\Authentication\Adapter\Ldap as LdapAdapter;
use Laminas\Authentication\AuthenticationService;
use Laminas\Authentication\Result;
class LdapAuthenticationMiddleware implements MiddlewareInterface
{
    private $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }
    /**
     * @inheritDoc
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        /*
         * Get values from php
         */
        $username = $request->getHeaderLine('PHP_AUTH_USER');
        $password = $request->getHeaderLine('PHP_AUTH_PW');
        /*
         * Ldap setup
         */
        $ldapOptions = $this->config['ldap'] ?? [];
        $adapter = new LdapAdapter($ldapOptions, $username, $password);

        /*
         * Authenticate to LDAP
         */
        $authenticationService = new AuthenticationService();
        $result = $authenticationService->authenticate($adapter);

        /*
         * Validate
         */
        if ($result->isValid())
        {
            $user = $result->getIdentity();
            return $handler->handle($request->withAttribute('user', $user));
        } else {
            return $this->createUnauthorizedResponse($request, $result);
        }

    }

    private function createUnauthorizedResponse(ServerRequestInterface $request, Result $result): ResponseInterface
    {
        /*
         * 401 response
         */
        $response = new EmptyResponse(401);
        $response = $response->withHeader('WWW-Authenticate', 'Header Authentication Required');

        return $response;
    }
}
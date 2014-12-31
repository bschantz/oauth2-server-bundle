<?php
/**
 * User: Brian Schantz
 * Date: 12/17/14
 * Time: 10:00 AM
 */

namespace OAuth2\ServerBundle\DependencyInjection\Security\Factory;


use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class OAuth2SecurityFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'oauth2.auth.id_token.provider.' . $id;
        $container
                ->setDefinition($providerId, new DefinitionDecorator('oauth2.auth.id_token.provider'))
                ->replaceArgument(0, new Reference($userProvider))
                ->replaceArgument(1, new Reference('oauth2.server'))
                ->replaceArgument(2, new Reference('oauth2.storage.public_key'));

        $listenerId = 'oauth2.auth.listener.' . $id;
        $container
                ->setDefinition($listenerId, new DefinitionDecorator('oauth2.auth.listener'))
                ->replaceArgument(0, new Reference('security.context'))
                ->replaceArgument(1, new Reference('security.authentication.manager'));

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    public function addConfiguration(NodeDefinition $builder)
    {
        // TODO: Implement addConfiguration() method.
    }

    public function getPosition()
    {
        return 'http';
    }

    public function getKey()
    {
        return 'oauth_jwt';
    }

}

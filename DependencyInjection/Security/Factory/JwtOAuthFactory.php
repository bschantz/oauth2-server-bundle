<?php
/**
 * User: bschantz
 * Date: 12/17/14
 * Time: 10:00 AM
 */

namespace OAuth2\ServerBundle\DependencyInjection\Security\Factory;


use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;

class JwtOAuthFactory implements SecurityFactoryInterface
{

    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        $providerId = 'security.authentication.provider.oauth_jwt.'.$id;
        $container
                ->setDefinition($providerId, new DefinitionDecorator('oauth_jwt.security.authentication.provider'))
                ->replaceArgument(0, new Reference($userProvider))
        ;

        $listenerId = 'security.authentication.listener.oauth_jwt.'.$id;
        $listener = $container->setDefinition($listenerId, new DefinitionDecorator('oauth_jwt.security.authentication.listener'));

        return array($providerId, $listenerId, $defaultEntryPoint);    }

    public function getPosition()
    {
        return 'pre_auth';
    }

    public function getKey()
    {
        return 'oauth_jwt';
    }

    public function addConfiguration(NodeDefinition $builder)
    {
        // TODO: Implement addConfiguration() method.
    }
}
 
<?php

namespace OAuth2\ServerBundle;

use OAuth2\ServerBundle\DependencyInjection\Security\Factory\OAuth2SecurityFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class OAuth2ServerBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new OAuth2SecurityFactory());
    }
}

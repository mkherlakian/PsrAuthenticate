<?php

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\AuthStore\AuthStore;
use Mauricek\PsrAuthentication\AuthProvider\AuthValidationProvider;
use Mauricek\PsrAuthentication\Middleware\ValidateTokenMiddleware;
use Mauricek\PsrAuthentication\Credentials;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Mauricek\PsrAuthentication\AuthProvider\JwtValidationProvider;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Prophecy\Argument;

class ValidateTokenMiddlewareTest extends TestCase
{
    protected function getValidationProvider($success = true)
    {
        $provider = $this->prophesize(JwtValidationProvider::class);
        $provider->validate(Argument::type(ServerRequestInterface::class))->willReturn(
            $success ? new Credentials('member_id', 'username', 'member') : null
        );

        return $provider->reveal();
    }

    protected function getRequest()
    {
        $request = $this->prophesize(ServerRequestInterface::class);

        $request
            ->withAttribute(Credentials::class, Argument::type(Credentials::class))
            ->willReturn($request);

        return $request->reveal();
    }

    protected function getDelegate($times = 1)
    {
        $response = $this->prophesize(ResponseInterface::class);

        $delegate = $this->prophesize(RequestHandlerInterface::class);
        $delegate
            ->handle(Argument::type(ServerRequestInterface::class))
            ->shouldBeCalledTimes($times)
            ->willReturn($response->reveal());

        return $delegate->reveal();
    }

    public function testSuccessfulAuth()
    {
        $provider = $this->getValidationProvider(true);

        $mw = new ValidateTokenMiddleware($provider);

        $mw->process($this->getRequest(), $this->getDelegate());

    }

    /**
     * @expectedException \Mauricek\PsrAuthentication\Exception\RuntimeException
     */
    public function testFailAuth()
    {
        $provider = $this->getValidationProvider(false);

        $mw = new ValidateTokenMiddleware($provider);

        $mw->process($this->getRequest(), $this->getDelegate(0));
    }

}

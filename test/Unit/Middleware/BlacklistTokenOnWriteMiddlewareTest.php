<?php

declare(strict_types=1);

namespace MauricekTest\AuthenticateTest\Middlewware;

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\Middleware\BlacklistTokenOnWriteMiddleware;
use Mauricek\PsrAuthentication\Authenticate;
use Mauricek\PsrAuthentication\TokenJti;
use Mauricek\PsrAuthentication\TokenExp;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Http\Message\ResponseInterface;
use Prophecy\Argument;

class BlacklistTokenOnWriteMiddlewareTest extends TestCase
{
    private function getRequestDouble($exp, $method = 'POST')
    {
        $request = $this->prophesize(ServerRequestInterface::class);
        $request->getAttribute(TokenJti::class)->willReturn(new TokenJti('abcd1234'));
        $request->getAttribute(TokenExp::class)->willReturn(new TokenExp($exp));
        $request->getMethod()->willReturn($method);

        return $request;
    }

    private function getResponseDouble($code = 200)
    {
        $response = $this->prophesize(ResponseInterface::class);
        $response->getStatusCode()->willReturn($code);

        return $response;
    }

    public function getAuthDouble($exp, $shouldBeCalledTimes = 1)
    {
        $authenticate = $this->prophesize(Authenticate::class);
        $resp = $authenticate->blacklistToken(
            new TokenJti('abcd1234'),
            new TokenExp($exp)
        );

        if($shouldBeCalledTimes > 0) {
            $resp->shouldBeCalledTimes($shouldBeCalledTimes);
        } else {
            $resp->shouldNotBeCalled();
        }

        return $authenticate;
    }

    private function getDelegateDouble($request, $code = 200)
    {
        $delegate = $this->prophesize(RequestHandlerInterface::class);
        $delegate->handle($request)->willReturn($this->getResponseDouble($code)->reveal());

        return $delegate;
    }

    public function testProcessSuccess()
    {
        $exp = time() + 3600;
        $request = $this->getRequestDouble($exp)->reveal();
        $delegate = $this->getDelegateDouble($request, 200);
        $authenticate = $this->getAuthDouble($exp, 1);
        $btowmw = new BlacklistTokenOnWriteMiddleware($authenticate->reveal(), ['invalidate_token_on_write' => true]);
        $btowmw->process($request, $delegate->reveal());
    }

    public function testProcessNot200()
    {
        $exp = time() + 3600;
        $request = $this->getRequestDouble($exp)->reveal();
        $delegate = $this->getDelegateDouble($request, 403);
        $authenticate = $this->getAuthDouble($exp, 0);
        $btowmw = new BlacklistTokenOnWriteMiddleware($authenticate->reveal(), ['invalidate_token_on_write' => true]);
        $btowmw->process($request, $delegate->reveal());
    }

    public function testProcessGet()
    {
        $exp = time() + 3600;
        $request = $this->getRequestDouble($exp, 'GET')->reveal();
        $delegate = $this->getDelegateDouble($request, 200);
        $authenticate = $this->getAuthDouble($exp, 0);
        $btowmw = new BlacklistTokenOnWriteMiddleware($authenticate->reveal(), ['invalidate_token_on_write' => true]);
        $btowmw->process($request, $delegate->reveal());
    }

    public function testProcessConfigFalse()
    {
        $exp = time() + 3600;
        $request = $this->getRequestDouble($exp)->reveal();
        $delegate = $this->getDelegateDouble($request, 200);
        $authenticate = $this->getAuthDouble($exp, 0);
        $btowmw = new BlacklistTokenOnWriteMiddleware($authenticate->reveal(), ['invalidate_token_on_write' => false]);
        $btowmw->process($request, $delegate->reveal());
    }
}

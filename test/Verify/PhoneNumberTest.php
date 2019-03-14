<?php

namespace MauricekTest\AuthenticateTest\Verify;

use PHPUnit\Framework\TestCase;
use Mauricek\PsrAuthentication\Verify\PhoneNumber;
use Assert;

class PhoneNumberTest extends TestCase
{
    protected $validNumbers = [
        '+1 123 456 777',
        '+89 1231 1231',
    ];

    protected $invalidNumbers = [
        ['123 123'],
        ['+adaf asda'],
        ['+1-123-45678'],
        ['+1 123'],
    ];

    public function testValidNumbers()
    {
        foreach($this->validNumbers as $number){
            $p = PhoneNumber::fromNumber($number);
            $this->assertEquals($number, $p->toString());
        }
    }

    /**
     * @dataProvider invalidNumbersProvider
     * @expectedException Assert\InvalidArgumentException
     */
    public function testInvalidNumbers($number)
    {
        $p = PhoneNumber::fromNumber($number);
    }

    public function invalidNumbersProvider()
    {
        return $this->invalidNumbers;
    }
}

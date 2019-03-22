<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication;

use Respect\Validation\Validator as v;
use Respect\Validation\Validatable;
use Respect\Validation\Exceptions\NestedValidationException;
use Respect\Validation\Exceptions\ValidationException;
use Mauricek\PsrAuthentication\MemberAdapter\CanRetrieveMember;
use Respect\Validation\Rules;

class LoginValidator
{
    protected $rules;
    protected $messages;

    final public function __construct()
    {
        $this->rules = $this->initRules();
    }

    public function initRules() : Validatable
    {
        return v::arrayType()
            ->key('email',      v::stringType()->notEmpty()->email())
            ->key('password',   v::stringType()->notEmpty()->noWhitespace()->alnum('! @ # $ % ^ \' & / : , { } [ ] ( ) - _')->length(8,64));

    }

    public function validate(array $input)
    {
        $success = true;

        try {
            $this->rules->assert($input);
        } catch (NestedValidationException $validationError) {
            $success = false;
            $this->messages = $validationError->getMessages();
        }

        return $success;
    }

    public function getMessages()
    {
        return $this->messages;
    }
}

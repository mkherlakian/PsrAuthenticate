<?php

namespace Mauricek\PsrAuthentication\Problems;

use Zend\ProblemDetails\Exception\ProblemDetailsExceptionInterface;
use Zend\ProblemDetails\Exception\CommonProblemDetailsExceptionTrait;

class UnreadableOrEmptyBody extends \Exception implements ProblemDetailsExceptionInterface
{

    use CommonProblemDetailsExceptionTrait;

    public function __construct($title, $type = '', $detail = '', $additionalData = [])
    {
        $this->title = $title;
        $this->type = $type;
        $this->detail = $detail;
        $this->additional = $additionalData;
        parent::__construct($title);
    }

    public function getStatus() : int
    {
        return 400;
    }
}

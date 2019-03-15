<?php

namespace Mauricek\PsrAuthentication\AuthStore;

use MongoDB\Client;
use Assert\Assertion;
use DateTime;
use DateInterval;

final class MongoDb
    implements AuthStore
{
    private $connection;

    //expire should be determined by config and injected here
    const REFRESH_TOKEN_COLL       = 'refresh_token';
    const TOKEN_BLACKLIST_COLL     = 'blacklist_token';
    const VERIFICATION_TOKEN_COLL  = 'verification_token';

    public function __construct(Client $connection, string $database, int $expireTime = 60*60*6)
    {
        $this->connection = $connection;
        $this->database   = $database;
        $this->expireTime = $expireTime;
    }

    public function getExpireTime() : int
    {
        return $this->expireTime;
    }

    private function getCollection(string $collection)
    {
        return $this
            ->connection
            ->{$this->database}
            ->{$collection};
    }

    public function fetchRefreshTokenById(string $id, bool $fetchExpired = false) : ?array
    {
       return $this->fetchRefreshToken('token_id', $id, $fetchExpired);
    }

    public function fetchRefreshTokenByToken(string $token, bool $fetchExpired = false) : ?array
    {
       return $this->fetchRefreshToken('token', $token, $fetchExpired);
    }

    protected function fetchRefreshToken(string $type = 'token_id', string $param, bool $fetchExpired = false) : ?array
    {
        Assertion::choice($type, ['token_id', 'token']);

        $cond = ['status' => 'ACTIVE', $type => $param];
        if(false == $fetchExpired) {
            $cond['issued_at'] = ['$lte' => new \MongoDB\BSON\UTCDateTime(
                (new DateTime())->add(new DateInterval("PT{$this->getExpireTime()}S"))
            ) ];
        }

        $result = $this
            ->getCollection(self::REFRESH_TOKEN_COLL)
            ->findOne(['status' => 'ACTIVE', $type => $param], ['projection' => ['_id' => 0]]);

        if($result) {
            $result['is_expired'] =
                $result['issued_at']->toDateTime()->add(new DateInterval("PT{$this->getExpireTime()}S")) < (new DateTime()) ? '1' : '0';

            $result->issued_at = $result->issued_at->toDateTime()->getTimestamp();
            $result->id = $result->token_id;
            unset($result->token_id);
        }

        return (array)$result;
    }

    public function createRefreshToken(string $id, string $token, string $role) : void
    {
        $this
            ->getCollection(self::REFRESH_TOKEN_COLL)
            ->insertOne([
                'token_id'  => $id,
                'token'     => $token,
                'role'      => $role,
                'status'    => 'ACTIVE',
                'issued_at' => new \MongoDB\BSON\UTCDateTime(),
            ]);
    }

    public function deleteExpiredTokens(string $id) : void
    {
        $this
            ->getCollection(self::REFRESH_TOKEN_COLL)
            ->updateMany(
                [
                    'token_id' => $id,
                    'status' => 'ACTIVE',
                    'issued_at' => [
                        '$lte' => new \MongoDB\BSON\UTCDateTime((new DateTime())->sub(new DateInterval("PT{$this->getExpireTime()}S")))
                    ]
                ],
                ['$set' => ['status' => 'DELETED_EXPIRED']]
            );
    }

    public function invalidateActiveTokens(string $id) : void
    {
        $this
            ->getCollection(self::REFRESH_TOKEN_COLL)
            ->updateMany(
                [
                    'token_id' => $id,
                    'issued_at' => ['$lte' => new \MongoDb\BSON\UTCDateTime()]
                ],
                ['$set' => ['status' => 'LOGGED_OUT']]
            );
    }

    public function updateRole(string $id, string $role) : void
    {
        $this
            ->getCollection(self::REFRESH_TOKEN_COLL)
            ->updateMany(['token_id' => $id], ['$set' => ['role' => $role]]);
    }

    public function blacklistToken(string $tokenId, int $expires) : void
    {
        $this
            ->getCollection(self::TOKEN_BLACKLIST_COLL)
            ->insertOne(['token_id' => $tokenId, 'expires' => new \MongoDB\BSON\UTCDateTime((new DateTime())->setTimestamp($expires))]);
    }

    public function isTokenBlacklisted(string $tokenId) : bool
    {
        //Delete old entries
        $this
            ->getCollection(self::TOKEN_BLACKLIST_COLL)
            ->deleteMany(['token_id' => $tokenId, 'expires' => new \MongoDB\BSON\UTCDateTime(
                (new DateTime())->sub(new DateInterval("PT10S"))
            )]);

        $results = $this
            ->getCollection(self::TOKEN_BLACKLIST_COLL)
            ->find(['token_id' => $tokenId])
            ->toArray();

        return count($results) > 0;
    }

    public function storeVerificationToken(string $id, string $method, string $token, string $status, ?int $expires = null) : void
    {
        $parameters = [
            'sub_id' => $id,
            'method' => $method,
            'token'  => $token,
            'status' => $status
        ];

        if(!is_null($expires)) {
            $parameters['expires'] = new \MongoDB\BSON\UTCDateTime((new DateTime())->setTimestamp($expires));
        }

        $this
            ->getCollection(self::VERIFICATION_TOKEN_COLL)
            ->updateOne(['sub_id' => $id, 'method' => $method, 'token' => $token], ['$set' => $parameters], ['upsert' => true]);
    }

    public function fetchVerificationToken(string $id, string $method, string $token, ?string $status = null) : ?array
    {
        $parameters = [
            'sub_id' => $id,
            'method' => $method,
            'token'  => $token,
        ];

        if(!is_null($status)) {
            $parameters['status'] = $status;
        }

        $result = $this
            ->getCollection(self::VERIFICATION_TOKEN_COLL)
            ->findOne($parameters);

        $result['id'] = $result['sub_id'];
        unset($result['sub_id']);

        return (array)$result;
    }
}

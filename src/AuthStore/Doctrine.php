<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\AuthStore;

use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Schema;
use Assert\Assertion;

final class Doctrine implements AuthStore
{
    //expire should be determined by config and injected here
    const REFRESH_TOKEN_TABLE   = 'refresh_token';
    const TOKEN_BLACKLIST_TABLE = 'blacklist_token';
    const VERIFICATION_TOKEN_TABLE = 'verification_token';

    private $connection;
    private $expireTime;

    public function __construct(Connection $connection, int $expireTime = 60*60*6)
    {
        $this->connection = $connection;
        $this->expireTime = $expireTime;
    }

    public function createTables()
    {
        $schema = new Schema();

        $refreshTokenTable = $schema->createTable(self::REFRESH_TOKEN_TABLE);
        $refreshTokenTable->addColumn("token",      "string", ["length" => 65]);
        $refreshTokenTable->addColumn("id",         "string", ["length" => 65]);
        $refreshTokenTable->addColumn("role",       "string", ["length" => 50]);
        $refreshTokenTable->addColumn("status",     "string", ["length" => 20]);
        $refreshTokenTable->addColumn("issued_at",  "integer");
        $refreshTokenTable->addUniqueIndex(["token"]);


        $queries = $schema->toSql($this->connection->getDatabasePlatform());
        var_dump($queries);
    }

    public function fetchRefreshTokenById(string $id, bool $fetchExpired = false) : ?array
    {
        return $this->fetchRefreshToken('id', $id, $fetchExpired);
    }

    public function fetchRefreshTokenByToken(string $token, bool $fetchExpired = false) : ?array
    {
        return $this->fetchRefreshToken('token', $token, $fetchExpired);
    }

    protected function fetchRefreshToken(string $type = 'id', string $param, bool $fetchExpired = false) : ?array
    {
        Assertion::choice($type, ['id', 'token']);

        $sql = sprintf(
            "SELECT *, (issued_at + %s < unix_timestamp()) AS is_expired FROM %s WHERE %s = :param AND status = :status",
            $this->expireTime,
            self::REFRESH_TOKEN_TABLE,
            $type
        );

        if(false == $fetchExpired) {
            $sql .= " AND issued_at + {$this->expireTime} > unix_timestamp()";
        }

        $stmt = $this->connection->prepare($sql);

        $stmt->bindValue('param', $param);
        $stmt->bindValue('status', 'ACTIVE');
        $stmt->execute();

        $result = $stmt->fetchAll();

        if(false === $result) {
            return null;
        }

        return $result;
    }

    public function deleteExpiredTokens(string $id) : void
    {
        //Delete expired tokens
        $stmt = $this->connection->prepare(
//            sprintf("DELETE FROM %s WHERE id = :id AND issued_at + %s < unix_timestamp()", self::REFRESH_TOKEN_TABLE, $this->expireTime)
            sprintf("UPDATE %s SET status = 'DELETED_EXPIRED' WHERE id = :id AND issued_at + %s < unix_timestamp() AND status='ACTIVE'", self::REFRESH_TOKEN_TABLE, $this->expireTime)
        );
        $stmt->bindValue('id', $id);
        $stmt->execute();
    }

    public function createRefreshToken(string $id, string $token, string $role) : void
    {
        $stmt = $this->connection->prepare(
            sprintf("INSERT INTO %s(id, token, role, status, issued_at) VALUES(:id, :token, :role, :status, unix_timestamp())", self::REFRESH_TOKEN_TABLE)
        );

        $stmt->bindValue(':id', $id);
        $stmt->bindValue(':token', $token);
        $stmt->bindValue(':role',  $role);
        $stmt->bindValue(':status', 'ACTIVE');

        $stmt->execute();
    }

    public function invalidateActiveTokens(string $id) : void
    {
        $stmt = $this->connection->prepare(
            sprintf("UPDATE %s SET status = 'LOGGED_OUT' WHERE id = :id AND issued_at < unix_timestamp()", self::REFRESH_TOKEN_TABLE)
        );

        $stmt->bindValue('id', $id);
        $stmt->execute();
    }

    public function updateRole(string $id, string $role) : void
    {
        $stmt = $this->connection->prepare(
            sprintf("UPDATE %s SET role = :role WHERE id = :id", self::REFRESH_TOKEN_TABLE)
        );

        $stmt->bindValue('id', $id);
        $stmt->bindValue('role', $role);
        $stmt->execute();
    }

    public function blacklistToken(string $tokenId, int $expires) : void
    {
        $stmt = $this->connection->prepare(
            sprintf("INSERT INTO %s(token_id, expires) VALUES (:token_id, :expires)", self::TOKEN_BLACKLIST_TABLE)
        );

        $stmt->bindValue('token_id', $tokenId);
        $stmt->bindValue('expires', $expires);
        $stmt->execute();
    }

    public function isTokenBlacklisted(string $tokenId) : bool
    {
        //clean up old  entries
        $stmt = $this->connection->prepare(
            sprintf("DELETE FROM %s WHERE token_id = :token_id AND expires + 10 < unix_timestamp()", self::TOKEN_BLACKLIST_TABLE)
        );

        $stmt = $this->connection->prepare(
            sprintf("SELECT COUNT(*) AS cnt FROM %s WHERE token_id = :token_id", self::TOKEN_BLACKLIST_TABLE)
        );

        $stmt->bindValue('token_id', $tokenId);
        $stmt->execute();
        $result = $stmt->fetch();

        return ($result['cnt'] > 0);
    }

    public function storeVerificationToken(string $id, string $method, string $token, string $status, ?int $expires = null) : void
    {
        $fields = ['id',   'method',  'token',  'status' ];
        $params  = [':id', ':method', ':token', ':status'];

        if(!is_null($expires)) {
            $fields[] = 'expires';
            $params[] = ':expires';
        }

        $stmt = $this->connection->prepare(
            sprintf(
                "INSERT INTO %s(%s) VALUES(%s) ON DUPLICATE KEY UPDATE status=:status",
                self::VERIFICATION_TOKEN_TABLE,
                implode(',', $fields),
                implode(',', $params)
            )
        );

        $stmt->bindValue('id',      $id);
        $stmt->bindValue('method',  $method);
        $stmt->bindValue('token',   $token);
        $stmt->bindValue('status',  $status);

        if(!is_null($expires)) {
            $stmt->bindValue('expires', $expires);
        }

        $stmt->execute();
    }

    public function fetchVerificationToken(string $id, string $method, string $token, ?string $status = null) : ?array
    {
        $sql = sprintf("SELECT * FROM %s WHERE id=:id AND token=:token", self::VERIFICATION_TOKEN_TABLE);
        if(!is_null($status)) {
            $sql .= " AND status = :status";
        }

        $stmt = $this->connection->prepare($sql);

        $stmt->bindValue('id',      $id);
        $stmt->bindValue('method',  $method);
        $stmt->bindValue('token',   $token);
        $stmt->bindValue('expires', $expires);

        if(!is_null($status)) {
            $stmt->bindValue('status',  $status);
        }

        $result = $stmt->fetchAll();

        if(false === $result) {
            return null;
        }

        return $result;
    }
}

<?php

declare(strict_types=1);

namespace Mauricek\PsrAuthentication\AuthStore;

interface AuthStore
{
    public function getExpireTime() : int;
    public function fetchRefreshTokenById(string $id, bool $fetchExpired = false) : ?array;
    public function fetchRefreshTokenByToken(string $token, bool $fetchExpired = false) : ?array;
    public function createRefreshToken(string $id, string $token, string $role) : void;
    public function deleteExpiredTokens(string $id) : void;
    public function invalidateActiveTokens(string $id) : void;
    public function updateRole(string $id, string $role) : void;
    public function blacklistToken(string $tokenId, int $expires) : void;
    public function isTokenBlacklisted(string $tokenId) : bool;

    public function storeVerificationToken(string $id, string $method, string $token, string $status, ?int $expires = null) : void;
    public function fetchVerificationToken(string $id, string $method, string $token, ?string $status = null) : ?array;
}

<?php

namespace MauricekTest\Integration\AuthStore;

use PHPUnit\Framework\TestCase;
use MongoDB\Client;
use Mauricek\PsrAuthentication\AuthStore\MongoDb as AuthStore;
use DateTime;
use DateInterval;

class MonogoDbTest extends TestCase {

    static $mongo;
    static $authStore;

    public static function setUpBeforeClass()
    {
        $config = require_once(dirname(__FILE__).'/../../config.php');
        $connectionString = $config['mongo_db']['connection'];
        $database = $config['mongo_db']['database'];

        $conn = new Client($connectionString);
        self::$mongo = $conn->{$database};

        //Drop collections before test
        self::$mongo->refresh_token->drop();
        self::$mongo->blacklist_token->drop();
        self::$mongo->verification_token->drop();

        self::$authStore = new AuthStore($conn, $database);

        //create an expired token
        self::$mongo->refresh_token->insertOne([
            'token_id'  => '8bdcd31f-1d26-43cc-9938-ed6b3094e501',
            'token'     => '5df7fba8-afd5-4d41-828d-b6255b8b0ef3',
            'role'      => 'member',
            'status'    => 'ACTIVE',
            'issued_at' => new \MongoDB\BSON\UTCDateTime((new DateTime())->sub(new DateInterval('PT86400S')))
        ]);
    }

    /**
    * @doesNotPerformAssertions
     */
    public function testCreateRefreshToken()
    {
        self::$authStore->createRefreshToken(
            'c44ce3d9-56ec-47a7-a858-6b0372b7770f',
            'f607c651-e092-42b2-bbcf-2ce61b961f3a',
            'member'
        );
    }

    /**
     * @depends testCreateRefreshToken
     */
    public function testFetchRefreshTokenById()
    {
        $token = self::$authStore->fetchRefreshTokenById('c44ce3d9-56ec-47a7-a858-6b0372b7770f');

        $this->assertEquals('c44ce3d9-56ec-47a7-a858-6b0372b7770f', $token['id']);
        $this->assertEquals('f607c651-e092-42b2-bbcf-2ce61b961f3a', $token['token']);
        $this->assertEquals('member', $token['role']);
        $this->assertEquals('ACTIVE', $token['status']);
    }

    /**
     * @depends testCreateRefreshToken
     */
    public function testFetchRefreshTokenByToken()
    {
        $token = self::$authStore->fetchRefreshTokenByToken('f607c651-e092-42b2-bbcf-2ce61b961f3a');

        $this->assertEquals('c44ce3d9-56ec-47a7-a858-6b0372b7770f', $token['id']);
        $this->assertEquals('f607c651-e092-42b2-bbcf-2ce61b961f3a', $token['token']);
        $this->assertEquals('member', $token['role']);
        $this->assertEquals('ACTIVE', $token['status']);
    }

    public function testDeleteExpiredTokens()
    {
        self::$authStore->deleteExpiredTokens('8bdcd31f-1d26-43cc-9938-ed6b3094e501');

        $token = (array)self::$mongo->refresh_token->findOne(['token_id' => '8bdcd31f-1d26-43cc-9938-ed6b3094e501']);

        $this->assertEquals('DELETED_EXPIRED', $token['status']);
    }

    /**
     * @depends testCreateRefreshToken
     */
    public function testInvalidateActiveToken()
    {
        self::$authStore->createRefreshToken('8bdcd31f-1d26-43cc-9938-ed6b3094e501', '8bdcd31f-1d26-43cc-9938-ed6b3094e501', 'member');

        self::$authStore->invalidateActiveTokens('8bdcd31f-1d26-43cc-9938-ed6b3094e501');

        $token = self::$mongo->refresh_token->findOne([
            'token_id' => '8bdcd31f-1d26-43cc-9938-ed6b3094e501'
        ]);

        $this->assertEquals('LOGGED_OUT', $token['status']);
    }

    /**
     * @depends testCreateRefreshToken
     */
    public function testUpdateRole()
    {
        self::$authStore->updateRole('c44ce3d9-56ec-47a7-a858-6b0372b7770f', 'admin');

        $token = self::$authStore->fetchRefreshTokenById('c44ce3d9-56ec-47a7-a858-6b0372b7770f');

        $this->assertEquals('admin', $token['role']);
    }

    public function testBlacklistToken()
    {
        $exp = time() + 3600;
        self::$authStore->blacklistToken('c44ce3d9-56ec-47a7-a858-6b0372b7770f', $exp);

        $token = (array)self::$mongo->blacklist_token->findOne(['token_id' => 'c44ce3d9-56ec-47a7-a858-6b0372b7770f']);

        $this->assertIsArray($token);
        $this->assertEquals('c44ce3d9-56ec-47a7-a858-6b0372b7770f', $token['token_id']);
        $this->assertEquals($exp, $token['expires']->toDateTime()->getTimestamp());
    }

    /**
     * @depends testBlacklistToken
     */
    public function testIsTokenBlacklisted()
    {
        $blacklisted = self::$authStore->isTokenBlacklisted('c44ce3d9-56ec-47a7-a858-6b0372b7770f');

        $this->assertTrue($blacklisted);
    }

    public function testStoreVerificationToken()
    {
        self::$authStore->storeVerificationToken(
            '62397242-463b-4eee-8ce1-13dffab3492f',
            'email',
            'ae1dd19a-6ddb-4c9d-8d35-48c18009c7bd',
            'ACTIVE'
        );

        //Test upsert, we shuould only have one result
        self::$authStore->storeVerificationToken(
            '62397242-463b-4eee-8ce1-13dffab3492f',
            'email',
            'ae1dd19a-6ddb-4c9d-8d35-48c18009c7bd',
            'ACTIVE'
        );

        $tokens = self::$mongo
            ->verification_token
            ->find(['sub_id' => '62397242-463b-4eee-8ce1-13dffab3492f'])->toArray();

        $this->assertIsArray($tokens);
        $this->assertCount(1, $tokens);
        $this->assertEquals('62397242-463b-4eee-8ce1-13dffab3492f', $tokens[0]['sub_id']);
        $this->assertEquals('ae1dd19a-6ddb-4c9d-8d35-48c18009c7bd', $tokens[0]['token']);
        $this->assertEquals('email', $tokens[0]['method']);
        $this->assertEquals('ACTIVE', $tokens[0]['status']);
    }

    /**
     * @depends testStoreVerificationToken
     */
    public function testFetchVerificationToken()
    {
        $token = self::$authStore->fetchVerificationToken(
            '62397242-463b-4eee-8ce1-13dffab3492f',
            'email',
            'ae1dd19a-6ddb-4c9d-8d35-48c18009c7bd'
        );

        $this->assertEquals('62397242-463b-4eee-8ce1-13dffab3492f', $token['id']);
        $this->assertEquals('ae1dd19a-6ddb-4c9d-8d35-48c18009c7bd', $token['token']);
        $this->assertEquals('email', $token['method']);
        $this->assertEquals('ACTIVE', $token['status']);
    }
}

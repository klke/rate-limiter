<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\RateLimiter\Tests;

use PHPUnit\Framework\TestCase;
use Symfony\Bridge\PhpUnit\ClockMock;
use Symfony\Component\RateLimiter\Exception\MaxWaitDurationExceededException;
use Symfony\Component\RateLimiter\Rate;
use Symfony\Component\RateLimiter\Storage\InMemoryStorage;
use Symfony\Component\RateLimiter\TokenBucket;
use Symfony\Component\RateLimiter\TokenBucketLimiter;

/**
 * @group time-sensitive
 */
class TokenBucketLimiterTest extends TestCase
{
    private $storage;

    protected function setUp(): void
    {
        $this->storage = new InMemoryStorage();

        ClockMock::register(TokenBucketLimiter::class);
        ClockMock::register(InMemoryStorage::class);
        ClockMock::register(TokenBucket::class);
    }

    public function testReserve()
    {
        $limiter = $this->createLimiter();

        $this->assertEquals(0, $limiter->reserve(5)->getWaitDuration());
        $this->assertEquals(0, $limiter->reserve(5)->getWaitDuration());
        $this->assertEquals(1, $limiter->reserve(5)->getWaitDuration());
    }

    public function testReserveMoreTokensThanBucketSize()
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Cannot reserve more tokens (15) than the burst size of the rate limiter (10).');

        $limiter = $this->createLimiter();
        $limiter->reserve(15);
    }

    public function testReserveMaxWaitingTime()
    {
        $this->expectException(MaxWaitDurationExceededException::class);

        $limiter = $this->createLimiter(10, Rate::perMinute());

        // enough free tokens
        $this->assertEquals(0, $limiter->reserve(10, 300)->getWaitDuration());
        // waiting time within set maximum
        $this->assertEquals(300, $limiter->reserve(5, 300)->getWaitDuration());
        // waiting time exceeded maximum time (as 5 tokens are already reserved)
        $limiter->reserve(5, 300);
    }

    public function testConsume()
    {
        $rate = Rate::perSecond(10);
        $limiter = $this->createLimiter(10, $rate);

        // enough free tokens
        $limit = $limiter->consume(5);
        $this->assertTrue($limit->isAccepted());
        $this->assertEquals(5, $limit->getRemainingTokens());
        $this->assertEqualsWithDelta(time(), $limit->getRetryAfter()->getTimestamp(), 1);
        // there are only 5 available free tokens left now
        $limit = $limiter->consume(10);
        $this->assertEquals(5, $limit->getRemainingTokens());

        $limit = $limiter->consume(5);
        $this->assertEquals(0, $limit->getRemainingTokens());
        $this->assertEqualsWithDelta(time(), $limit->getRetryAfter()->getTimestamp(), 1);
    }

    private function createLimiter($initialTokens = 10, Rate $rate = null)
    {
        return new TokenBucketLimiter('test', $initialTokens, $rate ?? Rate::perSecond(10), $this->storage);
    }
}

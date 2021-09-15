<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\RateLimiter;

use Symfony\Component\Lock\LockFactory;
use Symfony\Component\RateLimiter\Lock\NoLock;
use Symfony\Component\OptionsResolver\Options;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\RateLimiter\Policy\FixedWindowLimiter;
use Symfony\Component\RateLimiter\Policy\NoLimiter;
use Symfony\Component\RateLimiter\Policy\Rate;
use Symfony\Component\RateLimiter\Policy\SlidingWindowLimiter;
use Symfony\Component\RateLimiter\Policy\TokenBucketLimiter;
use Symfony\Component\RateLimiter\Storage\StorageInterface;
use Symfony\Component\OptionsResolver\Options as SymfonyOptions;

/**
 * @author Wouter de Jong <wouter@wouterj.nl>
 *
 * @experimental in 5.3
 */
final class RateLimiterFactory
{
    private $config;
    private $storage;
    private $lockFactory;

    public function __construct(array $config, StorageInterface $storage, LockFactory $lockFactory = null)
    {
        $this->storage = $storage;
        $this->lockFactory = $lockFactory;

        $this->config = [
            'id' => (isset($config['id']))?$config['id']:'',
            'policy' => (isset($config['policy']))?$config['policy']:'fixed_window',
            'limit' => (isset($config['limit']))?$config['limit']:10,
            'interval' => (new \DateTimeImmutable())->diff(new \DateTimeImmutable('+'.isset($config['interval'])?$config['interval']:'15 minutes')),
            'rate' => new Rate(
                (new \DateTimeImmutable())->diff(new \DateTimeImmutable('+'.isset($config['interval'])?$config['interval']:'15 minutes')),
                500
            )
        ];
    }

    public function create(string $key = null): LimiterInterface
    {
        $id = $this->config['id'].'-'.$key;
        $lock = $this->lockFactory ? $this->lockFactory->createLock($id) : new NoLock();

        switch ($this->config['policy']) {
            case 'token_bucket':
                return new TokenBucketLimiter($id, $this->config['limit'], $this->config['rate'], $this->storage, $lock);

            case 'fixed_window':
                return new FixedWindowLimiter($id, $this->config['limit'], $this->config['interval'], $this->storage, $lock);

            case 'sliding_window':
                return new SlidingWindowLimiter($id, $this->config['limit'], $this->config['interval'], $this->storage, $lock);

            case 'no_limit':
                return new NoLimiter();

            default:
                throw new \LogicException(sprintf('Limiter policy "%s" does not exists, it must be either "token_bucket", "sliding_window", "fixed_window" or "no_limit".', $this->config['policy']));
        }
    }
}

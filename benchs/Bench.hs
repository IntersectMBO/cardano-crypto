{-# LANGUAGE BangPatterns #-}
module Main where

import           Cardano.Crypto.Wallet
import           Control.DeepSeq                 (NFData, force)
import           Control.Exception               (evaluate)
import           Crypto.Random                   (getRandomBytes)
import           Data.ByteArray                  (Bytes)
import qualified Data.ByteArray                  as B
import qualified Data.ByteString                 as BS
import qualified Data.ByteString.Char8           as BC
import           Data.Bits                       (shiftR, xor)
import           GHC.Clock                       (getMonotonicTimeNSec)
import           Text.Printf                     (printf)

import qualified Crypto.Math.Edwards25519 as Edwards25519

hardIdx, softIdx :: DerivationIndex
hardIdx = 0x80000001
softIdx = 0x00000001

derivePass :: BS.ByteString
derivePass = BC.pack "DJVJa3#dtCgurH^cG&r53"

newPass :: BS.ByteString
newPass = BC.pack "lkjpO&*IwEUc!9LzmXSH^"

noDerivePass :: Bytes
noDerivePass = B.empty

benchMsg :: BS.ByteString
benchMsg = BC.pack "benchmark signing payload"

unwrap :: Show e => Either e a -> a
unwrap = either (error . show) id

mkLegacyNoPassXPrv :: Bytes -> XPrv
mkLegacyNoPassXPrv seed =
    unwrap $ xprv (secret <> pub <> chainCode)
  where
    seedBytes = B.convert seed :: BS.ByteString
    secret = seedBytes <> B.pack [32..63]
    scalar = Edwards25519.scalar seedBytes
    pub = Edwards25519.unPointCompressed (Edwards25519.scalarToPoint scalar)
    chainCode = B.pack [64..95]

benchmark :: NFData a => String -> Int -> IO a -> IO ()
benchmark name iterations action = do
    start <- getMonotonicTimeNSec
    loop iterations
    end <- getMonotonicTimeNSec
    let totalNs = end - start
        totalMs = fromIntegral totalNs / 1e6 :: Double
        avgMs = totalMs / fromIntegral iterations
    printf "%-24s total=%8.2f ms avg=%8.2f ms iterations=%d\n" name totalMs avgMs iterations
  where
    loop 0 = pure ()
    loop n = do
        result <- action
        _ <- evaluate (force result)
        loop (n - 1)

benchmarkIndexed :: NFData a => String -> Int -> (Int -> IO a) -> IO ()
benchmarkIndexed name iterations action = do
    start <- getMonotonicTimeNSec
    loop iterations
    end <- getMonotonicTimeNSec
    let totalNs = end - start
        totalMs = fromIntegral totalNs / 1e6 :: Double
        avgMs = totalMs / fromIntegral iterations
    printf "%-24s total=%8.2f ms avg=%8.2f ms iterations=%d\n" name totalMs avgMs iterations
  where
    loop 0 = pure ()
    loop n = do
        result <- action n
        _ <- evaluate (force result)
        loop (n - 1)

tweakSeed :: Bytes -> Int -> Bytes
tweakSeed seed n = B.pack $ zipWith xor seedBytes stream
  where
    seedBytes = B.unpack seed
    stream = cycle
        [ fromIntegral n
        , fromIntegral (n `shiftR` 8)
        , fromIntegral (n `shiftR` 16)
        , fromIntegral (n `shiftR` 24)
        ]

main :: IO ()
main = do
    seed <- getRandomBytes 32 :: IO Bytes
    let !parentPass = unwrap $ generate seed derivePass
        !parentNoPass = unwrap $ generate seed noDerivePass
        !legacyNoPass = mkLegacyNoPassXPrv seed

    putStrLn "cardano-crypto benchmark (production v2 KDF policy)"
    putStrLn "Argon2id: 128 MiB, t=3, p=4"
    putStrLn ""

    benchmark "derive-v1-hard-nopass" 50 $ pure $ unwrap $ deriveXPrv DerivationScheme1 noDerivePass parentNoPass hardIdx
    benchmark "derive-v2-hard-nopass" 50 $ pure $ unwrap $ deriveXPrv DerivationScheme2 noDerivePass parentNoPass hardIdx
    benchmark "derive-v1-soft-pass" 50 $ pure $ unwrap $ deriveXPrv DerivationScheme1 derivePass parentPass softIdx
    benchmark "derive-v2-soft-pass" 50 $ pure $ unwrap $ deriveXPrv DerivationScheme2 derivePass parentPass softIdx
    benchmarkIndexed "create-v2" 5 $ \n -> pure $ unwrap $ generate (tweakSeed seed n) derivePass
    benchmark "validate-passphrase" 5 $ pure $ unwrap $ validateXPrvPassphrase derivePass parentPass
    benchmark "sign-v2" 5 $ pure $ unwrap $ sign derivePass parentPass benchMsg
    benchmark "change-passphrase" 5 $ pure $ unwrap $ xPrvChangePass derivePass newPass parentPass
    benchmark "legacy-v1-to-v2" 5 $ pure $ unwrap $ upgradeXPrvToV2 noDerivePass legacyNoPass

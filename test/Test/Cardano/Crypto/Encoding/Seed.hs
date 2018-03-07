{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE Rank2Types #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeOperators #-}

module Test.Cardano.Crypto.Encoding.Seed
    ( tests
    ) where

import Foundation
import Foundation.Check
import Foundation.String (words)
import Basement.Nat

import Crypto.Encoding.BIP39
import Crypto.Encoding.BIP39.English (english)

import Crypto.Error (throwCryptoError)

import Cardano.Crypto.Encoding.Seed as PW

-- -------------------------------------------------------------------------- --
--                            Encoding/Seed                                   --
-- -------------------------------------------------------------------------- --

tests :: Test
tests = Group "Seed (paper-wallet)"
    [ go (Proxy @128)
    , go (Proxy @160)
    , go (Proxy @192)
    , go (Proxy @224)
    , testVectorPaperWallet
    ]
  where
    go :: forall n m s
        . ( PW.ConsistentEntropy n m s
          , PW.ConsistentEntropy (n + PW.IVSizeBits) (m + PW.IVSizeWords) (CheckSumBits (n + PW.IVSizeBits))
          , Arbitrary (PW.Entropy n)
          )
       => Proxy n
       -> Test
    go pr = Property ("unscramble . scramble @" <> sz <> " == id") $ \iv (e :: PW.Entropy n) p ->
        let s = PW.scramble @n iv e p
            u = PW.unscramble s p
         in e === u
      where
         sz = show $ natVal pr

testVectorPaperWallet :: Test
testVectorPaperWallet = Group "PaperWallet"
    [ mkTestVector (Proxy @128) testVector128
    , mkTestVector (Proxy @160) testVector160
    , mkTestVector (Proxy @192) testVector192
    , mkTestVector (Proxy @224) testVector224
    ]

mkTestVector :: forall n ns mw mws csz cszs
              . ( ConsistentEntropy n mw csz
                , ConsistentEntropy ns mws cszs
                , (n + IVSizeBits) ~ ns
                , (mw + IVSizeWords) ~ mws
                )
             => Proxy n
             -> [(Passphrase, MnemonicPhrase mw, MnemonicPhrase mws, ScrambleIV)]
             -> Test
mkTestVector proxyN l = Group ("Test Vector for entropy size: " <> show n) $
    mkTest @n proxyN <$> l
  where
    n :: Int
    n = fromIntegral $ natVal proxyN

mkTest :: forall n ns mw mws csz cszs
        . ( ConsistentEntropy n mw csz
          , ConsistentEntropy ns mws cszs
          , (n + IVSizeBits) ~ ns
          , (mw + IVSizeWords) ~ mws
          )
       => Proxy n
       -> (Passphrase, MnemonicPhrase mw, MnemonicPhrase mws, ScrambleIV)
       -> Test
mkTest _ (passphrase, mnemonicwords, scrambledref, iv) = Property (show mnemonicwords) $
    let mw = mnemonicPhraseToMnemonicSentence @mw english mnemonicwords
     in case wordsToEntropy @n mw of
        Nothing -> propertyFail "cannot generate entropy from mnemonic in test vector..."
        Just e  ->
            let scrambled = scramble @n iv e passphrase
                mws       = entropyToWords @ns scrambled
                mw'       = mnemonicSentenceToMnemonicPhrase @mws english mws
             in scrambledref === mw'

testVector128 :: [(Passphrase, MnemonicPhrase 12, MnemonicPhrase 15, ScrambleIV)]
testVector128 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase $ words "legal winner thank year wave sausage worth useful legal winner thank yellow")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase ["abandon","abandon","abandon","win","nest","chef","want","salt","join","shove","minor","december","miss","oak","name"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    , ( "Cardano Ada"
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase $ words "place document tooth joy hospital gift unlock resource tooth supply claim try")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase ["abandon","amount","liberty","main","village","tube","salute","frost","capital","that","apology","grunt","peasant","rich","aim"])
      , throwCryptoError $ mkScrambleIV "\0\1\2\3"
      )
    , ( "This is a very long passphrase. This is a very long passphrase. This is a very long passphrase. This is a very long passphrase."
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase $ words "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase ["clay","eyebrow","melt","enroll","lend","fold","card","pledge","allow","bottom","dirt","road","frame","fatal","arch"])
      , throwCryptoError $ mkScrambleIV "\42\42\42\42"
      )
    ]

testVector160 :: [(Passphrase, MnemonicPhrase 15, MnemonicPhrase 18, ScrambleIV)]
testVector160 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase $ words "tail island situate hill mechanic retreat negative uncle layer faith behave harbor kitchen sock relief")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase ["abandon","abandon","ability","sand","moon","arm","symbol","early","jazz","brand","message","depart","taste","absent","rubber","remind","spell","faculty"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

testVector192 :: [(Passphrase, MnemonicPhrase 18, MnemonicPhrase 21, ScrambleIV)]
testVector192 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase $ words "erosion find kingdom cable glue umbrella bid capital chat trial pass matter nose vault bring quote enforce sketch")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase  ["abandon","abandon","abandon","ostrich","soda","horror","crumble","note","tenant","axis","black","message","prevent","harbor","ladder","humor","purse","account","mango","fluid","life"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

testVector224 :: [(Passphrase, MnemonicPhrase 21, MnemonicPhrase 24, ScrambleIV)]
testVector224 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase $ words "strong student orbit sugar dune live long fitness wide goat famous fitness equal degree much enforce divide subject dizzy clip legend")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (mnemonicPhrase ["abandon","abandon","ability","profit","snow","pyramid","ritual","sunny","acquire","derive","wonder","credit","rate","minor","scissors","swim","dirt","brief","inflict","rate","retreat","blast","image","include"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

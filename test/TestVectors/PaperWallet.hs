{-# LANGUAGE Rank2Types           #-}
{-# LANGUAGE DataKinds            #-}
{-# LANGUAGE TypeFamilies         #-}
{-# LANGUAGE TypeOperators        #-}
{-# LANGUAGE TypeApplications     #-}
{-# LANGUAGE NoImplicitPrelude    #-}
{-# LANGUAGE ConstraintKinds      #-}
{-# LANGUAGE OverloadedStrings    #-}
{-# LANGUAGE ScopedTypeVariables  #-}
{-# LANGUAGE FlexibleContexts     #-}

module TestVectors.PaperWallet
    ( testVectorPaperWallet
    ) where

import Foundation
import Foundation.String
import Foundation.Check
import Basement.Nat
import Crypto.Error
import Data.List ((!!), elemIndex)

import Cardano.Crypto.Encoding.Seed
import Crypto.Encoding.BIP39 (wordsToEntropy,entropyToWords, unWordIndex,wordIndex)
import qualified Crypto.Encoding.BIP39.English as BIP39English
import           Basement.Sized.List (ListN)
import qualified Basement.Sized.List as ListN



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
             -> [(Passphrase, ListN mw String, ListN mws String, ScrambleIV)]
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
       -> (Passphrase, ListN mw String, ListN mws String, ScrambleIV)
       -> Test
mkTest _ (passphrase, mnemonicwords, scrambledref, iv) = Property (show mnemonicwords) $
    let dictLookup x = BIP39English.words !! fromIntegral (unWordIndex x)
        dictRevLookup x = maybe (error $ "word not in the english dictionary: " <>  x) (wordIndex . fromIntegral) $ x `elemIndex` BIP39English.words
        mw = ListN.map dictRevLookup mnemonicwords
    in case wordsToEntropy @n mw of
        Nothing -> error "cannot generate entropy from mnemonic in test vector..."
        Just e  ->
            let scrambled = scramble @n iv e passphrase
                mws       = entropyToWords @ns scrambled
                mw'       = ListN.map dictLookup mws
             in scrambledref === mw'

testVector128 :: [(Passphrase, ListN 12 String, ListN 15 String, ScrambleIV)]
testVector128 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "legal winner thank year wave sausage worth useful legal winner thank yellow")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN ["picnic","leave","file","debris","evolve","bring","toilet","response","run","inch","clean","wheel","abandon","abandon","actress"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    , ( "Cardano Ada"
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "legal winner thank year wave sausage worth useful legal sausage inch year")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN ["anxiety","urge","mirror","fade","parrot","hurt","junior","fabric","history","screen","gravity","craft","coral","above","actor"])
      , throwCryptoError $ mkScrambleIV "\0\1\2\3"
      )
    , ( "This is a very long passphrase. This is a very long passphrase. This is a very long passphrase. This is a very long passphrase."
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN  ["actor","dinner","buddy","room","pig","face","boat","net","anger","quiz","planet","engage","pencil","bench","prison"])
      , throwCryptoError $ mkScrambleIV "\42\42\42\42"
      )
    ]

testVector160 :: [(Passphrase, ListN 15 String, ListN 18 String, ScrambleIV)]
testVector160 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "legal winner thank year wave sausage worth useful legal winner thank yellow clean inch leave")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN ["obvious","evidence","slow","embark","worry","proof","ignore","ordinary","debris","sibling","hunt","kind","tonight","feed","village","abandon","abandon","across"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

testVector192 :: [(Passphrase, ListN 18 String, ListN 21 String, ScrambleIV)]
testVector192 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "legal winner thank year wave sausage worth useful legal winner thank yellow clean inch leave picnic file debris")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN ["shop","magnet","gaze","course","option","obscure","mouse","wing","flat","ticket","decade","ill","monster","tell","vivid","simple","practice","trend","abandon","abandon","arm"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

testVector224 :: [(Passphrase, ListN 21 String, ListN 24 String, ScrambleIV)]
testVector224 =
    [ ( mempty
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "legal winner thank year wave sausage worth useful legal winner thank yellow clean inch leave picnic file debris simple decade wing")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN ["robust","portion","original","miracle","armed","scout","glance","danger","cost","cannon","warrior","raise","select","illegal","tiger","burger","sad","tuna","mutual","fancy","source","abandon","abandon","arrange"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

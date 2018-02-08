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
        mw :: MnemonicSentence mw = ListN.toListN_ $ dictRevLookup <$> ListN.unListN mnemonicwords
    in case wordsToEntropy @n mw of
        Nothing -> error "cannot generate entropy from mnemonic in test vector..."
        Just e  ->
            let scrambled = scramble @n iv e passphrase
                mws       = entropyToWords @ns scrambled
                mw' :: ListN mws String = ListN.toListN_ $ dictLookup <$> ListN.unListN mws
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
                  (ListN.toListN ["option","rubber","service","cost","burden","track","edge","forward","diesel","merry","pull","elite","abandon","abandon","actor"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    , ( "This is a very long passphrase. This is a very long passphrase. This is a very long passphrase. This is a very long passphrase."
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN $ words "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong")
      , fromMaybe (error "test vector's mnemoic sentence not enough elements")
                  (ListN.toListN  ["imitate","judge","beyond","truck","model","width","stool","rally","extend","trip","filter","army","abandon","abandon","actress"])
      , throwCryptoError $ mkScrambleIV "\0\0\0\0"
      )
    ]

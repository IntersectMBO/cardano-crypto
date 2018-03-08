{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE TypeFamilies #-}

module Main (main) where

import Basement.Nat
import qualified Basement.Sized.List as LN

import Foundation
import Foundation.Check
import qualified Foundation.Parser as Parser
import Foundation.Collection ((!), nonEmpty_)
import Foundation.String
import Foundation.String.Builder (emit)
import Foundation.String.Read (readIntegral)
import Basement.Block (Block)

import Data.List (elemIndex)

import Inspector

import Data.ByteArray (Bytes, convert)
import qualified Data.ByteArray as B

import           Cardano.Crypto.Wallet
import           Cardano.Crypto.Encoding.Seed
import           Cardano.Crypto.Encoding.BIP39
import           Crypto.Encoding.BIP39.English (english)
import qualified Cardano.Crypto.Praos.VRF as VRF

import Test.Orphans

main :: IO ()
main = defaultMain $ do
    goldenBIP39
    goldenHDWallet
    goldenPaperwallet
    goldenVRF

type GoldenVRF
    = "cardano" :> "crypto" :> "VRF"
      :> Payload "random"  VRF.SecretKey
      :> Payload "message" String
      :> Payload "secret"  VRF.SecretKey
      :> ( Payload "output" Bytes
         , Payload "proof" VRF.Proof
         )

goldenVRF :: GoldenT ()
goldenVRF = golden (Proxy :: Proxy GoldenVRF) $ \r msg sec ->
    first convert (VRF.generate' r msg sec)

-- -------------------------------------------------------------------------- --

type GoldenPaperWallet n
    = "cardano" :> "crypto" :> PathParameter "scramble" n
      :> Payload "iv"     ScrambleIV
      :> Payload "input" (Mnemonic 'English (MnemonicWords n))
      :> Payload "passphrase" Passphrase
      :> Payload "shielded_input" (Mnemonic 'English (MnemonicWords (n + IVSizeBits)))

goldenPaperwallet :: GoldenT ()
goldenPaperwallet = group $ do
    golden (Proxy :: Proxy (GoldenPaperWallet 128)) $ \iv (Mnemonic input) pw ->
        Mnemonic (scrambleMnemonic (Proxy @128) iv input pw)
    golden (Proxy :: Proxy (GoldenPaperWallet 160)) $ \iv (Mnemonic input) pw ->
        Mnemonic (scrambleMnemonic (Proxy @160) iv input pw)
    golden (Proxy :: Proxy (GoldenPaperWallet 192)) $ \iv (Mnemonic input) pw ->
        Mnemonic (scrambleMnemonic (Proxy @192) iv input pw)
    golden (Proxy :: Proxy (GoldenPaperWallet 224)) $ \iv (Mnemonic input) pw ->
        Mnemonic (scrambleMnemonic (Proxy @224) iv input pw)

-- -------------------------------------------------------------------------- --

type HDWallet n
    = "cardano" :> "crypto" :> "wallet" :> PathParameter "BIP39-" n
      :> Payload "words" (Mnemonic 'English (MnemonicWords n))
      :> Payload "passphrase" Passphrase
      :> Payload "derivation-scheme" DerivationScheme
      :> Payload "path" ChainCodePath
      :> Payload "data-to-sign" String
      :> ( Payload "xPub" XPub
         , Payload "xPriv" XPrv
         , Payload "signature" XSignature
         , Payload "seed" Seed
         )

goldenHDWallet :: GoldenT ()
goldenHDWallet = group $ do
    summary "This test vectors uses the `Cardano.Crypto.Wallet` primitives to produce extended\n\
            \private keys which are _encrypted_ with a passphrase. A passphrase can be empty as well.\n\
            \Under this schema, we support only hardened key derivation."

    golden (Proxy :: Proxy (HDWallet 128)) (runTest (Proxy @128))
    golden (Proxy :: Proxy (HDWallet 160)) (runTest (Proxy @160))
    golden (Proxy :: Proxy (HDWallet 192)) (runTest (Proxy @192))
    golden (Proxy :: Proxy (HDWallet 224)) (runTest (Proxy @224))
    golden (Proxy :: Proxy (HDWallet 256)) (runTest (Proxy @256))
  where
    runTest :: forall n csz mw . ConsistentEntropy n mw csz
            => Proxy n
            -> Mnemonic 'English mw
            -> Passphrase
            -> DerivationScheme
            -> ChainCodePath
            -> String
            -> (XPub, XPrv, XSignature, Seed)
    runTest p (Mnemonic mw) pw ds (Root path) toSign =
        let -- 1. retrieve the seed
            seed = fromMaybe (error "Invalid Mnemonic, cannot retrieve the `Seed'")
                             (cardanoSlSeed p mw)
            -- 2. generate from the seed
            master = generate seed pw
            -- 3. get the XPrv from the master and the path
            priv = deriveWith master path
            -- 4. get the public key
            pub = toXPub priv
            -- 5. sign some data
            s = sign pw priv toSign
         in (pub, priv, s, seed)
      where
        deriveWith :: XPrv -> [Word32] -> XPrv
        deriveWith = foldl' (deriveXPrv ds pw)

-- -------------------------------------------------------------------------- --

type BIP39 n
    = "crypto" :> "encoding" :> PathParameter "BIP39-" n
      :> Payload "words" (Mnemonic 'English (MnemonicWords n))
      :> Payload "passphrase" Passphrase
      :> ( Payload "entropy" (Entropy n)
         , Payload "seed" Seed
         )

goldenBIP39 :: GoldenT ()
goldenBIP39 = group $ do
    summary "Test official BIP39"

    golden (Proxy :: Proxy (BIP39 128)) (runTest (Proxy @128))
    -- golden (Proxy :: Proxy (BIP39 160)) (runTest (Proxy @160))
    golden (Proxy :: Proxy (BIP39 192)) (runTest (Proxy @192))
    -- golden (Proxy :: Proxy (BIP39 224)) (runTest (Proxy @224))
    golden (Proxy :: Proxy (BIP39 256)) (runTest (Proxy @256))
  where
    runTest :: forall n csz mw . ConsistentEntropy n mw csz
            => Proxy n
            -> Mnemonic 'English mw
            -> Passphrase
            -> (Entropy n, Seed)
    runTest p (Mnemonic mw) pw  =
        let -- 1. retrieve the entroy
            entropy = fromMaybe (error "invalid mnemonic phrase")
                                (wordsToEntropy @n mw)
            -- 2. retrieve the seed
            seed = sentenceToSeed @mw mw english pw
         in (entropy, seed)

-- -------------------------------------------------------------------------- --
--                          Helpers                                           --
-- -------------------------------------------------------------------------- --

-- | `m/0'/1'/1000'`
newtype ChainCodePath = Root [Word32]
  deriving (Show, Eq, Typeable)
instance Arbitrary ChainCodePath where
    arbitrary = Root <$> arbitrary
instance Inspectable ChainCodePath where
    documentation _ = "derivation code: `m[([0-9]+|[0-9]+')]*`"
    exportType _ Rust = exportType (Proxy @[Word32]) Rust
    exportType _ t    = exportType (Proxy @String) t
    display Rust (Root l) = display Rust l
    display t (Root l) = display t (intercalate "/" ((:) "m" $ f <$> l))
      where
        f :: Word32 -> String
        f w
          | w >= 0x80000000 = show (w - 0x80000000) <> "'"
          | otherwise       = show w
    parser _ = do
        Parser.elements "\"m"
        l <- Parser.many $ do
                Parser.element '/'
                r <- Parser.takeWhile (`elem` ['0'..'9'])
                mh <- Parser.optional $ Parser.element '\''
                r' <- maybe (Parser.reportError $ Parser.Expected "Word32" r) pure $ readIntegral r
                pure $ case mh of
                    Nothing -> r'
                    Just () -> r' + 0x80000000
        Parser.element '"'
        pure $ Root l

-- Enum for the support language to read/write from mnemonic
data Language = English

-- | a convenient type to help read/parse/document expected input of type
-- BIP39 mnemonics
newtype Mnemonic (k :: Language) n = Mnemonic (MnemonicSentence n)
  deriving (Eq, Typeable)

instance Arbitrary (Mnemonic 'English 12) where
    arbitrary = Mnemonic . entropyToWords @128 @4 @12 <$> arbitrary
instance Arbitrary (Mnemonic 'English 15) where
    arbitrary = Mnemonic . entropyToWords @160 @5 @15 <$> arbitrary
instance Arbitrary (Mnemonic 'English 18) where
    arbitrary = Mnemonic . entropyToWords @192 @6 @18 <$> arbitrary
instance Arbitrary (Mnemonic 'English 21) where
    arbitrary = Mnemonic . entropyToWords @224 @7 @21 <$> arbitrary
instance Arbitrary (Mnemonic 'English 24) where
    arbitrary = Mnemonic . entropyToWords @256 @8 @24 <$> arbitrary

instance Inspectable (Mnemonic 'English 12) where
    display Rust (Mnemonic l) = display Rust (maybe undefined entropyRaw $ wordsToEntropy @128 @4 @12 l)
    display t (Mnemonic l) = display t (mnemonicSentenceToString english l)
    documentation _ = "UTF8 BIP39 passphrase (english)"
    exportType _ Rust = emit "[u8;16]"
    exportType _ t = exportType (Proxy @String) t
    parser _ = do
        strs <- words <$> parser Proxy
        Mnemonic <$> case mnemonicPhrase @12 strs of
            Nothing -> Parser.reportError $ Parser.Expected (show n <> " words") (show (length strs) <> " words")
            Just l  -> pure $ mnemonicPhraseToMnemonicSentence english l
      where
        n = natVal @12 Proxy

instance Inspectable (Mnemonic 'English 15) where
    display Rust (Mnemonic l) = display Rust (maybe undefined entropyRaw $ wordsToEntropy @160 @5 @15 l)
    display t (Mnemonic l) = display t (mnemonicSentenceToString english l)
    documentation _ = "UTF8 BIP39 passphrase (english)"
    exportType _ Rust = emit "[u8;20]"
    exportType _ t = exportType (Proxy @String) t
    parser _ = do
        strs <- words <$> parser Proxy
        Mnemonic <$> case mnemonicPhrase @15 strs of
            Nothing -> Parser.reportError $ Parser.Expected (show n <> " words") (show (length strs) <> " words")
            Just l  -> pure $ mnemonicPhraseToMnemonicSentence english l
      where
        n = natVal @15 Proxy

instance Inspectable (Mnemonic 'English 18) where
    display Rust (Mnemonic l) = display Rust (maybe undefined entropyRaw $ wordsToEntropy @192 @6 @18 l)
    display t (Mnemonic l) = display t (mnemonicSentenceToString english l)
    documentation _ = "UTF8 BIP39 passphrase (english)"
    exportType _ Rust = emit "[u8;24]"
    exportType _ t = exportType (Proxy @String) t
    parser _ = do
        strs <- words <$> parser Proxy
        Mnemonic <$> case mnemonicPhrase @18 strs of
            Nothing -> Parser.reportError $ Parser.Expected (show n <> " words") (show (length strs) <> " words")
            Just l  -> pure $ mnemonicPhraseToMnemonicSentence english l
      where
        n = natVal @18 Proxy

instance Inspectable (Mnemonic 'English 21) where
    display Rust (Mnemonic l) = display Rust (maybe undefined entropyRaw $ wordsToEntropy @224 @7 @21 l)
    display t (Mnemonic l) = display t (mnemonicSentenceToString english l)
    documentation _ = "UTF8 BIP39 passphrase (english)"
    exportType _ Rust = emit "[u8;28]"
    exportType _ t = exportType (Proxy @String) t
    parser _ = do
        strs <- words <$> parser Proxy
        Mnemonic <$> case mnemonicPhrase @21 strs of
            Nothing -> Parser.reportError $ Parser.Expected (show n <> " words") (show (length strs) <> " words")
            Just l  -> pure $ mnemonicPhraseToMnemonicSentence english l
      where
        n = natVal @21 Proxy

instance Inspectable (Mnemonic 'English 24) where
    display Rust (Mnemonic l) = display Rust (maybe undefined entropyRaw $ wordsToEntropy @256 @8 @24 l)
    display t (Mnemonic l) = display t (mnemonicSentenceToString english l)
    documentation _ = "UTF8 BIP39 passphrase (english)"
    exportType _ Rust = emit "[u8;32]"
    exportType _ t = exportType (Proxy @String) t
    parser _ = do
        strs <- words <$> parser Proxy
        Mnemonic <$> case mnemonicPhrase @24 strs of
            Nothing -> Parser.reportError $ Parser.Expected (show n <> " words") (show (length strs) <> " words")
            Just l  -> pure $ mnemonicPhraseToMnemonicSentence english l
      where
        n = natVal @24 Proxy

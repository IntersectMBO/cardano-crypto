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
import Foundation.String.Read (readIntegral)

import Data.List (elemIndex)

import Inspector
import Inspector.Display
import Inspector.Parser

import           Cardano.Crypto.Wallet
import           Cardano.Crypto.Encoding.Seed
import           Crypto.Encoding.BIP39
import qualified Crypto.Encoding.BIP39.English as English

main :: IO ()
main = defaultMain $ do
    goldenPaperwallet
    goldenHDWallet

-- -------------------------------------------------------------------------- --

type GoldenPaperWallet n
    = "cardano" :> "crypto" :> PathParameter "scramble" n
      :> Payload "iv"     ScrambleIV
      :> Payload "input" (Mnemonic 'English (MnemonicWords n))
      :> Payload "passphrase" Passphrase
      :> Payload "shielded_input" (Mnemonic 'English (MnemonicWords (n + IVSizeBits)))

goldenPaperwallet :: GoldenT ()
goldenPaperwallet = do
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
         )

goldenHDWallet :: GoldenT ()
goldenHDWallet = do
    golden (Proxy :: Proxy (HDWallet 128)) runTest
    golden (Proxy :: Proxy (HDWallet 160)) runTest
    golden (Proxy :: Proxy (HDWallet 192)) runTest
    golden (Proxy :: Proxy (HDWallet 224)) runTest
    golden (Proxy :: Proxy (HDWallet 256)) runTest
  where
    runTest (Mnemonic mw) pw ds (Root path) toSign =
        let -- 1. retrieve the seed
            seed = sentenceToSeed mw englishDict "TREZOR"
            -- 2. generate from the seed
            master = generate seed pw
            -- 3. get the XPrv from the master and the path
            priv = deriveWith master path
            -- 4. get the public key
            pub = toXPub priv
            -- 5. sign some data
            s = sign pw priv toSign
         in (pub, priv, s)
      where
        deriveWith :: XPrv -> [Word32] -> XPrv
        deriveWith = foldl' (deriveXPrv ds pw)

-- -------------------------------------------------------------------------- --
--                          Helpers                                           --
-- -------------------------------------------------------------------------- --

-- | `m/0'/1'/1000'`
newtype ChainCodePath = Root [Word32]
  deriving (Show, Eq, Typeable)
instance Arbitrary ChainCodePath where
    arbitrary = Root <$> arbitrary
instance Display ChainCodePath where
    display (Root l) = "\"" <> intercalate "/" ((:) "m" $ f <$> l) <> "\""
      where
        f :: Word32 -> String
        f w
          | w >= 0x80000000 = show (w - 0x80000000) <> "'"
          | otherwise       = show w

instance HasParser ChainCodePath where
    getParser = do
        Parser.elements "\"m"
        l <- Parser.many $ do
                Parser.element '/'
                r <- Parser.takeWhile (`elem` ['0'..'9'])
                mh <- Parser.optional $ Parser.element '\''
                r' <- maybe (reportError $ Expected "Integer" r) pure $ readIntegral r
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

instance (KnownNat n, NatWithinBound Int n) => Arbitrary (Mnemonic 'English n) where
    arbitrary = do
        r <- LN.replicateM @n (elements $ nonEmpty_ English.words)
        pure $ Mnemonic $ LN.map (dictionaryWordToIndex englishDict) r

instance Display (Mnemonic 'English n) where
    display (Mnemonic l) = "\"" <> intercalate " " (LN.unListN $ LN.map (dictionaryIndexToWord englishDict) l) <> "\""
instance (KnownNat n, NatWithinBound Int n) => HasParser (Mnemonic 'English n) where
    getParser = do
        strs <- words <$> strParser
        Mnemonic <$> case LN.toListN @n strs of
            Nothing -> reportError $ Expected (show n <> " words") (show (length strs) <> " words")
            Just l  -> pure $ LN.map (dictionaryWordToIndex englishDict) l
      where
        n = natVal (Proxy @n)

englishDict :: Dictionary
englishDict = Dictionary dictLookup dictRevLookup " "
  where
    dictLookup :: WordIndex -> String
    dictLookup x = fromMaybe (error $ "not a valid BIP39 English word: " <> show x)
                 $ English.words ! fromIntegral (unWordIndex x)
    dictRevLookup :: String -> WordIndex
    dictRevLookup x = maybe (error $ "word not in the english dictionary: " <> x)
                            (wordIndex . fromIntegral)
                            (x `elemIndex` English.words)

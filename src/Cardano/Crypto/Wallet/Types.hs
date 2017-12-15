{-# LANGUAGE PatternSynonyms #-}
module Cardano.Crypto.Wallet.Types
    ( ChainCode(..)
    , DerivationScheme(..)
    , pattern LatestScheme
    ) where

import           Control.DeepSeq (NFData)
import           Data.ByteArray  (ByteArrayAccess)
import           Data.ByteString (ByteString)
import           Data.Hashable   (Hashable)

data DerivationScheme = DerivationScheme1
    deriving (Show, Eq, Ord, Enum, Bounded)

pattern LatestScheme :: DerivationScheme
pattern LatestScheme = DerivationScheme1

newtype ChainCode = ChainCode ByteString
    deriving (Show, Eq, Ord, ByteArrayAccess, NFData, Hashable)

module Cardano.Crypto.Wallet.Types
    ( ChainCode(..)
    ) where

import           Control.DeepSeq (NFData)
import           Data.ByteArray  (ByteArrayAccess)
import           Data.ByteString (ByteString)
import           Data.Hashable   (Hashable)

newtype ChainCode = ChainCode ByteString
    deriving (Show, Eq, Ord, ByteArrayAccess, NFData, Hashable)

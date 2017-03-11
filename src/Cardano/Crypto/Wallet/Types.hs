module Cardano.Crypto.Wallet.Types
    ( ChainCode(..)
    ) where

import           Control.DeepSeq (NFData)
import           Data.ByteArray  (ByteArrayAccess, convert)
import qualified Data.ByteArray  as B (append, length, splitAt)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B (pack)
import           Data.Hashable   (Hashable)

newtype ChainCode = ChainCode ByteString
    deriving (Show, Eq, Ord, ByteArrayAccess, NFData, Hashable)

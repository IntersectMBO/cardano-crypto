{-# LANGUAGE CPP #-}

module Encoding (setEncoding) where

#if mingw32_HOST_OS
import           System.IO (IO, hSetEncoding, stdout, stderr, utf8)
#endif

setEncoding :: IO ()
#if mingw32_HOST_OS
setEncoding = do
  hSetEncoding stdout utf8
  hSetEncoding stderr utf8
#else
setEncoding = return ()
#endif

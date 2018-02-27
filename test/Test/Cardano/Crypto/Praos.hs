{-# LANGUAGE OverloadedStrings #-}

module Test.Cardano.Crypto.Praos
    ( tests
    ) where

import Foundation.Check

import qualified Test.Cardano.Crypto.Praos.VRF as VRF

tests :: Test
tests = Group "Praos"
    [ VRF.tests
    ]

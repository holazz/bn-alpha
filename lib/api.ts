import type { Hex } from 'viem'
import type { AlphaTokenInfo, TransactionActionMap } from '@/types'
import axios from 'axios'
import { zeroAddress } from 'viem'
import { apiKeys } from '@/configs'
import { WBNB_ADDRESS } from '@/constants'
import { getRandomElementFromArray } from '@/lib/utils'

const client = axios.create({
  baseURL: 'https://api.bscscan.com/api',
})

client.interceptors.request.use(
  (config) => {
    if (config.params) {
      if (config.params.action === 'txlist') {
        config.params.apikey = getRandomElementFromArray(apiKeys.txlist)
      }
      else if (config.params.action === 'txlistinternal') {
        config.params.apikey = getRandomElementFromArray(apiKeys.txlistinternal)
      }
      else if (config.params.action === 'tokentx') {
        config.params.apikey = getRandomElementFromArray(apiKeys.tokentx)
      }
      else {
        config.params.apikey = getRandomElementFromArray(apiKeys.default)
      }
    }
    return config
  },
  (error) => {
    console.error('Request error:', error)
    return Promise.reject(error)
  },
)

async function fetchTokenPriceFromCryptoCompare(symbol: string): Promise<number> {
  const resolvedSymbol = symbol === 'WBNB' ? 'BNB' : symbol
  const res = await axios.get('https://min-api.cryptocompare.com/data/price', {
    params: { fsym: resolvedSymbol, tsyms: 'USD' },
  })
  if (res.data?.Message?.includes('does not exist')) {
    throw new Error(`CryptoCompare doesn't support ${resolvedSymbol}`)
  }
  return res.data.USD
}

async function fetchTokenPriceFromGeckoTerminal(symbol: string, address: Hex): Promise<number> {
  const resolvedAddress = ['BNB', 'WBNB'].includes(symbol) ? zeroAddress : address.toLowerCase()
  const res = await axios.get(`https://api.geckoterminal.com/api/v2/simple/networks/bsc/token_price/${resolvedAddress}`)
  const price = res.data?.data?.attributes?.token_prices?.[resolvedAddress]
  if (price === undefined) {
    throw new Error(`GeckoTerminal price not found for ${address}`)
  }
  return Number(price)
}

async function fetchTokenPriceFromDexScreener(symbol: string, address: Hex): Promise<number> {
  const resolvedAddress = symbol === 'BNB' ? WBNB_ADDRESS.toLowerCase() : address.toLowerCase()
  const res = await axios.get(`https://api.dexscreener.com/latest/dex/tokens/${resolvedAddress}`)
  const price = res.data.pairs.filter((pair: any) => pair.chainId === 'bsc')?.[0]?.priceUsd
  if (!price) {
    throw new Error(`DexScreener price not found for ${address}`)
  }
  return Number(price)
}

export async function getTokenPrice({ symbol, address }: { symbol: string, address: Hex }): Promise<number> {
  if (symbol === 'USDT')
    return 1

  const priceFetchStrategies = [
    () => fetchTokenPriceFromCryptoCompare(symbol),
    () => fetchTokenPriceFromGeckoTerminal(symbol, address),
    () => fetchTokenPriceFromDexScreener(symbol, address),
  ]

  for (const strategy of priceFetchStrategies) {
    try {
      const price = await strategy()
      if (price !== undefined)
        return price
    }
    catch (e: any) {
      console.warn(`Price fetch failed: ${e.message}`)
    }
  }
  throw new Error('All token price fetching strategies failed')
}

export async function getBlockNumberByTimestamp(timestamp: number) {
  const res = await client.get('', {
    params: {
      module: 'block',
      action: 'getblocknobytime',
      timestamp,
      closest: 'before',
    },
  })
  const blockNumber = Number(res.data.result)
  return Number.isNaN(blockNumber) ? 99999999 : blockNumber
}

export async function getAlphaTokens(): Promise<AlphaTokenInfo[]> {
  const res = await axios.get(
    'https://www.binance.com/bapi/defi/v1/public/wallet-direct/buw/wallet/cex/alpha/all/token/list',
  )
  return res.data.data.filter((token: AlphaTokenInfo) => token.chainId === '56')
}

export async function getSpotTokens(): Promise<string[]> {
  const res = await axios.get(
    'https://api.binance.com/api/v3/exchangeInfo',
  )
  return res.data.symbols.map((symbol: { baseAsset: string }) => symbol.baseAsset)
}

export async function getTransactions<T extends keyof TransactionActionMap>({
  action,
  address,
  startblock = 0,
  endblock = 99999999,
}: {
  action: T
  address: Hex
  startblock?: number
  endblock?: number
}): Promise<TransactionActionMap[T][]> {
  const res = await client.get<{ result: TransactionActionMap[T][] }>('', {
    params: {
      module: 'account',
      action,
      address,
      startblock,
      endblock,
      sort: 'desc',
    },
  })
  if (typeof res.data.result === 'string' && (res.data.result as string)?.includes('rate limit reached')) {
    console.log(res.config.params.action, res.config.params.apikey)
    throw new Error('Max daily rate limit reached. 110000 (100%) of 100000 day/limit')
  }
  return res.data.result
}

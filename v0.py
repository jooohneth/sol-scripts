import asyncio
import websockets
import json
import base64
from solders.pubkey import Pubkey  # type: ignore
from solders.token.state import Mint
import struct
from solana.rpc.api import Client
from solana.rpc.commitment import Commitment

# WSS = "wss://mainnet.helius-rpc.com/v0?api-key=b1545fe5-e778-488c-a0ac-ad858a87a520"
WSS = "wss://newest-few-liquid.solana-mainnet.quiknode.pro/e77852f2b3e2c7e42fb99918d199d10cd400e0b2"

def parse_event_data(data_hex):
    try:
        data_bytes = bytes.fromhex(data_hex)
        offset = 8

        def read_length_prefixed_string(data, offset):
            try:
                length = struct.unpack('<I', data[offset:offset + 4])[0]
                offset += 4
                string_data = data[offset:offset + length]
                offset += length
                return string_data.decode('utf-8').strip('\x00'), offset
            except Exception as e:
                print(f"Error reading length-prefixed string: {e}")
                raise

        def read_pubkey(data, offset):
            try:
                pubkey_data = data[offset:offset + 32]
                offset += 32
                pubkey = str(Pubkey.from_bytes(pubkey_data))
                return pubkey, offset
            except Exception as e:
                print(f"Error reading pubkey: {e}")
                raise

        event_data = {}
        event_data['name'], offset = read_length_prefixed_string(data_bytes, offset)
        event_data['symbol'], offset = read_length_prefixed_string(data_bytes, offset)
        event_data['uri'], offset = read_length_prefixed_string(data_bytes, offset)
        event_data['mint'], offset = read_pubkey(data_bytes, offset)
        event_data['bonding_curve'], offset = read_pubkey(data_bytes, offset)
        event_data['user'], offset = read_pubkey(data_bytes, offset)

        return event_data
    except Exception as e:
        print(f"Error parsing event data: {e}")
        raise

async def logs_subscribe():
    try:
        async with websockets.connect(WSS) as websocket:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "logsSubscribe",
                "params": [
                    {"mentions": ["6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"]}, 
                    {"commitment": "processed"}
                ]
            }

            try:
                await websocket.send(json.dumps(request))
                print("Subscribed to logs...")
            except Exception as e:
                print(f"Error sending subscription request: {e}")
                return

            parsed_events = set()

            while True:
                try:
                    response = await websocket.recv()
                    log_data = json.loads(response)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")
                    continue
                except Exception as e:
                    print(f"Error receiving or processing response: {e}")
                    continue

                logs = log_data.get("params", {}).get("result", {}).get("value", {}).get("logs", [])
                
                if "Instruction: InitializeMint2" in ''.join(logs):
                    for log_entry in logs:
                        if "Program data: " in log_entry and not log_entry.startswith("Program data: vdt/"):
                            try:
                                program_data_base64 = log_entry.split("Program data: ")[1]
                                program_data_bytes = base64.b64decode(program_data_base64)
                                program_data_hex = program_data_bytes.hex()
                            except Exception as e:
                                print(f"Error decoding base64 program data: {e}")
                                continue
                            
                            try:
                                event_data = parse_event_data(program_data_hex)
                                # Add metadata to event_data
                                metadata = get_program_metadata(event_data['mint'])
                                event_data['metadata'] = metadata
                                event_data_json = json.dumps(event_data)
                                print("----------------------------------------------------------------")
                                if event_data_json not in parsed_events:
                                    parsed_events.add(event_data_json)
                                    print(f"{event_data_json},")
                            except Exception as e:
                                print(f"Error processing event data: {e}")
                                
    except Exception as e:
        print(f"Error in logs subscription: {e}")


def get_program_metadata(mint_address: str) -> dict:
    """
    Fetch metadata for a given program/token mint address.
    Returns a dictionary containing account metadata including freeze authority if present.
    """
    try:
        client = Client("https://api.mainnet-beta.solana.com")
        mint_address = Pubkey.from_string(mint_address)
        
        # Fetch the account info
        response = client.get_account_info(
            mint_address,
            commitment=Commitment("confirmed"),
            encoding="base64"
        )
        
        # Access the response correctly
        account_info = response.value
        if account_info is None:
            return {"error": "Account not found"}

        # Parse the account data
        metadata = {
            "mint_address": str(mint_address),
            "executable": account_info.executable,
            "owner": str(account_info.owner),
            "lamports": account_info.lamports,
            "rent_epoch": account_info.rent_epoch,
            "data_len": len(account_info.data) if account_info.data else 0,
        }

    except Exception as e:
        return {"error": f"Failed to fetch metadata: {str(e)}"}
        
    if account_info.data:
        try:
            # Decode the base64 data correctly
            if len(account_info.data) >= 82:  # Full mint data
                mint_data = Mint.from_bytes(account_info.data)
                freeze_authority_option = mint_data.freeze_authority  
                metadata["freeze_authority"] = str(freeze_authority_option) if freeze_authority_option else None
        except Exception as e:
            metadata["data_parse_error"] = str(e)

    return metadata



# Example usage in your evaluate_token function:
def evaluate_token(token_data):
    # ... existing code ...
    metadata = get_program_metadata(mint_address)
    
    if "freeze_authority" in metadata:
        print(f"Warning: Token has freeze authority: {metadata['freeze_authority']}")
        # You might want to reject tokens with freeze authority
        return False

def can_sell_token(token_address):
    # Add logic to simulate a sell transaction
    # This function would check if selling is allowed
    return True  # Placeholder for actual implementation

if __name__ == "__main__":
    try:
        asyncio.run(logs_subscribe())
    except Exception as e:
        print(f"Unexpected error in main event loop: {e}")
// Code generated by falafel 0.9.1. DO NOT EDIT.
// source: taprootassets.proto

// +build js

package taprpc

import (
	"context"

	gateway "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
)

func RegisterTaprootAssetsJSONCallbacks(registry map[string]func(ctx context.Context,
	conn *grpc.ClientConn, reqJSON string, callback func(string, error))) {

	marshaler := &gateway.JSONPb{
		MarshalOptions: protojson.MarshalOptions{
			UseProtoNames:   true,
			EmitUnpopulated: true,
		},
	}

	registry["taprpc.TaprootAssets.ListAssets"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ListAssetRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ListAssets(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.ListUtxos"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ListUtxosRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ListUtxos(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.ListGroups"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ListGroupsRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ListGroups(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.ListBalances"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ListBalancesRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ListBalances(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.ListTransfers"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ListTransfersRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ListTransfers(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.StopDaemon"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &StopRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.StopDaemon(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.DebugLevel"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &DebugLevelRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.DebugLevel(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.QueryAddrs"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &QueryAddrRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.QueryAddrs(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.NewAddr"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &NewAddrRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.NewAddr(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.DecodeAddr"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &DecodeAddrRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.DecodeAddr(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.AddrReceives"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &AddrReceivesRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.AddrReceives(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.VerifyProof"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ProofFile{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.VerifyProof(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.ExportProof"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ExportProofRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ExportProof(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.ImportProof"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &ImportProofRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.ImportProof(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.SendAsset"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &SendAssetRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.SendAsset(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.GetInfo"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &GetInfoRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.GetInfo(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}

	registry["taprpc.TaprootAssets.SubscribeSendAssetEventNtfns"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &SubscribeSendAssetEventNtfnsRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		stream, err := client.SubscribeSendAssetEventNtfns(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		go func() {
			for {
				select {
				case <-stream.Context().Done():
					callback("", stream.Context().Err())
					return
				default:
				}

				resp, err := stream.Recv()
				if err != nil {
					callback("", err)
					return
				}

				respBytes, err := marshaler.Marshal(resp)
				if err != nil {
					callback("", err)
					return
				}
				callback(string(respBytes), nil)
			}
		}()
	}

	registry["taprpc.TaprootAssets.FetchAssetMeta"] = func(ctx context.Context,
		conn *grpc.ClientConn, reqJSON string, callback func(string, error)) {

		req := &FetchAssetMetaRequest{}
		err := marshaler.Unmarshal([]byte(reqJSON), req)
		if err != nil {
			callback("", err)
			return
		}

		client := NewTaprootAssetsClient(conn)
		resp, err := client.FetchAssetMeta(ctx, req)
		if err != nil {
			callback("", err)
			return
		}

		respBytes, err := marshaler.Marshal(resp)
		if err != nil {
			callback("", err)
			return
		}
		callback(string(respBytes), nil)
	}
}

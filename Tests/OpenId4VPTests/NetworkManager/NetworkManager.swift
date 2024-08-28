import Foundation
@testable import OpenId4VP

class MockNetworkManager: NetworkManaging {
    var response: HTTPURLResponse?
    var error: Error?

    func sendHTTPPostRequest(requestBody: String, url: URL) async throws -> String? {
        if error != nil {
            throw NetworkRequestException.networkRequestFailed(message: "Network Request failed with error response: response")
        }
        return "Success: Request completed successfully."
    }
}

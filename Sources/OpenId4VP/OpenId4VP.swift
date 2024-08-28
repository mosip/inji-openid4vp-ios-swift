import Foundation

public class OpenId4VP {
    let traceabilityId: String
    let networkManager: NetworkManaging
    var authorizationRequest: AuthorizationRequest?
    private var presentationDefinitionId: String?
    private var responseUri: String?
    
    init(traceabilityId: String, networkManager: NetworkManaging? = nil) {
        self.traceabilityId = traceabilityId
        self.networkManager = networkManager ?? NetworkManager.shared
    }
    
    public func setPresentationDefinitionId(_ id: String) {
        self.presentationDefinitionId = id
    }
    
    public func setResponseUri(_ responseUri: String){
        self.responseUri = responseUri
    }
    
    public func authenticateVerifier(encodedAuthorizationRequest: String, trustedVerifierJSON: [[Verifier]]) async throws -> AuthenticationResponse {
        
        Logger.setLogTag(className:String(describing: type(of: self)), traceabilityId: traceabilityId)
        
        do {
            authorizationRequest =  try AuthorizationRequest.getAuthorizationRequest(encodedAuthorizationRequest: encodedAuthorizationRequest, setResponseUri: setResponseUri)
            
            return try AuthenticationResponse.getAuthenticationResponse(authorizationRequest!, trustedVerifierJSON, setPresentationDefinitionId: setPresentationDefinitionId)
            
        } catch(let exception) {
            await sendErrorToResponseUri(error: exception, uri: responseUri!)
            throw exception
        }
    }
    
    public func constructVerifiablePresentationToken(credentialsMap: [String: [String]]) async throws ->  String? {
        
        return try AuthorizationResponse.constructVpForSigning(credentialsMap)
    }
    
    public func shareVerifiablePresentation(vpResponseMetadata: VPResponseMetadata) async throws -> String? {
        
        do {
            return try await AuthorizationResponse.shareVp(vpResponseMetadata: vpResponseMetadata,nonce: authorizationRequest!.nonce, responseUri: authorizationRequest!.responseUri,presentationDefinitionId: presentationDefinitionId!, networkManager: networkManager)
        } catch(let exception) {
            await sendErrorToResponseUri(error: exception, uri: responseUri!)
            throw exception
        }
    }
    
    private func sendErrorToResponseUri(error: Error, uri: String) async {
        
        Logger.getLogTag(className: String(describing: type(of: self)))
        
        guard let url = URL(string: uri) else { return }
        
        let errorInfo = """
        {
            "error": \(error),
            "traceabilityId": \(traceabilityId)
        }
        """
        
        do {
            let response =  try await networkManager.sendHTTPPostRequest(requestBody: errorInfo, url: url)
            print("\(String(describing: response))")
        } catch {
            Logger.error("Unexpected error occurred while sending the error to verifier: \(error)")
        }
    }
}

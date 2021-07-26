package policy

//---------------------------------------------------------------------------------------
type cPolicy struct {
	Source     string `json:"source" validate:"omitempty,min=3,max=64,alphanum"`
	Destinaton string `json:"destination" validate:"omitempty,min=3,max=64,alphanum"`
	//Location       string `json:"location" validate:"omitempty,min=3,max=64,alphanum"`
	//SourceCNT      string `json:"source_country" validate:"omitempty,min=3,max=64,alphanum"`
	//DestinationCNT string `json:"destination_country" validate:"omitempty,min=3,max=64,alphanum"`
	//Schedule       string `json:"schedule" validate:"omitempty,min=3,max=64,alphanum"`
	//User           string `json:"user" validate:"omitempty,min=3,max=64,alphanum"`
	//Group          string `json:"group" validate:"omitempty,min=3,max=64,alphanum"`
}

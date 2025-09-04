// SPDX-License-Identifier: GPL-3.0-only

package notifications

type NotificationTypes string

const (
	Email NotificationTypes = "EMAIL"
)

type NotificationData struct {
	To        string         `json:"to"`
	ToName    *string        `json:"to_name,omitempty"`
	Template  string         `json:"template"`
	Variables map[string]any `json:"variables,omitempty"`
}

type NotificationProviders string

const (
	ZeptoMail NotificationProviders = "zepto_mail"
	Mock      NotificationProviders = "mock"
)

type ZeptoMailRequest struct {
	TemplateKey   string               `json:"template_key,omitempty"`
	TemplateAlias string               `json:"template_alias,omitempty"`
	BounceAddress string               `json:"bounce_address,omitempty"`
	From          ZeptoMailAddress     `json:"from"`
	To            []ZeptoMailRecipient `json:"to"`
	MergeInfo     map[string]any       `json:"merge_info,omitempty"`
	ReplyTo       *ZeptoMailAddress    `json:"reply_to,omitempty"`
}

type ZeptoMailRecipient struct {
	EmailAddress ZeptoMailAddress `json:"email_address"`
}

type ZeptoMailAddress struct {
	Address string  `json:"address"`
	Name    *string `json:"name,omitempty"`
}

type ZeptoMailResponse struct {
	Data      []ZeptoMailData `json:"data,omitempty"`
	Message   string          `json:"message,omitempty"`
	RequestID string          `json:"request_id,omitempty"`
	Object    string          `json:"object,omitempty"`
	Error     *ZeptoMailError `json:"error,omitempty"`
}

type ZeptoMailData struct {
	Code           string              `json:"code"`
	AdditionalInfo []map[string]string `json:"additional_info,omitempty"`
	Message        string              `json:"message"`
}

type ZeptoMailError struct {
	Code      string                 `json:"code,omitempty"`
	Details   []ZeptoMailErrorDetail `json:"details,omitempty"`
	Message   string                 `json:"message"`
	RequestID string                 `json:"request_id,omitempty"`
}

type ZeptoMailErrorDetail struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Target      string `json:"target"`
	TargetValue string `json:"target_value,omitempty"`
}

type ZeptoMailErrorResponse struct {
	Error     ZeptoMailError `json:"error"`
	RequestID string         `json:"request_id,omitempty"`
}

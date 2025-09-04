// SPDX-License-Identifier: GPL-3.0-only

package notifications

import (
	"fmt"
	"qdroid-server/commons"
)

func DispatchNotification(_type NotificationTypes, provider NotificationProviders, data NotificationData) error {
	commons.Logger.Debugf("Dispatching notification:\n- type=%s\n- provider=%s", _type, provider)

	var err error
	switch _type {
	case Email:
		mockEmail := commons.GetEnv("MOCK_EMAIL_NOTIFICATIONS")
		if mockEmail == "true" {
			commons.Logger.Debug("Mock email notifications enabled, using mock provider")
			provider = Mock
		}
		err = dispatchEmail(provider, data)
	default:
		err = fmt.Errorf("unsupported notification type: %s", _type)
	}

	if err != nil {
		commons.Logger.Errorf("Failed to dispatch notification:\n%v", err)
		return err
	}

	commons.Logger.Infof("Notification dispatched successfully:\n- type=%s\n- provider=%s", _type, provider)
	return nil
}

func dispatchEmail(provider NotificationProviders, data NotificationData) error {
	switch provider {
	case ZeptoMail:
		return ZeptoMailClient(data)
	case Mock:
		return MockEmailClient(data)
	default:
		return fmt.Errorf("unsupported email provider: %s", provider)
	}
}
